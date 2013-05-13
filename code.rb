require 'securerandom'
require 'base64'
require 'celluloid'
require 'has_guarded_handlers'
require 'pry'

module HasGuardedHandlers
  module ClassMethods
    def execute_guarded_handlers_on_receiver
      execute_block_on_receiver :register_handler, :register_tmp_handler, :register_handler_with_priority
    end
  end
end

class Message
  def initialize(id, source)
    @id = id || SecureRandom.hex(6)
    @source = source
  end
  attr_reader :id, :source
end

class Request < Message
  def initialize(source)
    super(nil, source)
  end
end

class PingRequest < Request
  def make_reply(peer)
    PingResponse.new(@id, peer)
  end
end

class PingResponse < Message
end

class FindNodeRequest < Request
  def initialize(source, key)
    super(source)
    @key = key
  end
  attr_reader :key

  def make_reply(peer, peers)
    FindNodeResponse.new(@id, peer, peers)
  end
end

class FindNodeResponse < Message
  def initialize(id, source, peers)
    super(id, source)
    @peers = peers
  end
  attr_reader :peers
end

class Key
  SIZE = 160

  def self.zero
    new(Array.new(SIZE/ 8, 0).pack("C*"))
  end

  def self.random(size = SIZE)
    if size % 8 > 0
      raise "Invalid key size: #{size.inspect}"
    end
    data = SecureRandom.random_bytes(size / 8)
    new(data)
  end

  def initialize(data)
    @data = data
  end
  attr_reader :data

  def xor(key)
    unless key.size == size
      raise "Incompatible key sizes: expected #{size.inspect}, got #{key.size.inspect}"
    end
    xor_bytes = key.bytes.zip(bytes).map do |(a,b)|
      a ^ b
    end
    self.class.new(xor_bytes.pack("C*"))
  end

  def first_set_bit_index
    #p bytes
    bytes.each_with_index do |byte,byte_index|
      #p(byte_index: byte_index, byte: byte)
      next if byte == 0
      7.downto(0) do |bit_index|
        #p(bit_index: bit_index)
        unless byte & (1 << bit_index) == 0
          return (bytes.to_a.size - byte_index - 1) * 8 + bit_index
        end
      end
    end
    nil
  end

  def bytes
    @data.bytes
  end

  def size
    bytes.to_a.size * 8
  end

  def id
    Base64.urlsafe_encode64(@data)
  end

  def inspect
    "#<Key:#{object_id.to_s(16)} size=#{size.inspect} id=#{id.inspect}>"
  end
end

class Peer
  def initialize(key, ip, port)
    @key = key
    @ip = ip
    @port = port
    @last_contact = nil
  end
  attr_reader :key, :ip, :port

  def contacted?
    @last_contact
  end

  def contacted!
    @last_contact = Time.now
  end
end

class Bucket
  def initialize(max_size)
    @max_size = max_size
    @list = []
    @peers = {}
  end

  def peers
    @peers.values.sort_by do |peer|
      @list.index(peer.key.data)
    end
  end

  def count
    @list.size
  end

  def insert(peer)
    return unless peer.contacted?

    return if @list.include?(peer.key.data)

    if @list.size == @max_size
      @peers.delete(@list.fetch(0))
      @list.delete_at(0)
    end

    @list.insert(0, peer.key.data)
    @peers[peer.key.data] = peer
  end
end

class Buckets
  SIZE = 20
  def initialize(local_peer)
    @local_peer = local_peer
    @bucket_size = SIZE
    @data = Array.new(Key::SIZE) { Bucket.new(@bucket_size) }
  end

  def insert(peer)
    if index = index_for(peer.key)
      @data[index].insert(peer)
    end
  end

  def closest_for(key)
    closest = []

    index = index_for(key)
    index ||= 0

    closest += @data.fetch(index).peers

    i = 1
    while closest.size < @bucket_size
      closest += @data.fetch(index + i).peers if index + i < @data.size
      closest += @data.fetch(index - i).peers if index - i >= 0

      if @data.size <= index + i && index - i < 0
        break
      end
      i += 1
    end

    closest
  end

  def index_for(key)
    key.xor(@local_peer.key).first_set_bit_index
  end

  def peer_count
    @data.map(&:count).inject(&:+)
  end

  def inspect
    "#<Buckets:#{object_id.to_s(16)} known-peers=#{peer_count}>"
  end
end

class FindNode
  def initialize(key, node)
    @key = key
    @node = node

    @queried = Set.new
    @querying = {}
  end

  def run
    @closest = @node.buckets.closest_for(@key)
    @closest << @node.peer
    queried(@node.peer)

    loop do
      if peer = next_unqueried
        #puts "trying to find #{@key.inspect} using #{peer.key.inspect}"
        message = FindNodeRequest.new(@node.peer, @key)
        @querying[peer.key.data] = Celluloid::Actor.current.future.call(peer, message, FindNodeResponse)
      elsif @querying.any?
        #puts "waiting for #{@querying.size} replies to find nodes"
        @querying.values.map(&:value).each do |reply|
          puts "got reply with #{reply.peers.size} peers"
          queried(reply.source)
          reply.peers.each do |peer|
            unless querying?(peer) || queried?(peer)
              @closest << peer
            end
          end
        end
      end

      # TODO: sort @closest by xor distance to @key
      @closest.slice!(Buckets::SIZE..-1)

      break unless more?
    end

    @closest
  end

  def more?
    @querying.any? || @queried & @closest == @queried
  end

  def next_unqueried
    @closest.each do |peer|
      unless querying?(peer) || queried?(peer)
        @querying[peer.key.data] = nil
        return peer
      end
    end
    nil
  end

  def querying?(peer)
    @querying.keys.include?(peer.key.data)
  end

  def queried(peer)
    @querying.delete(peer.key.data)
    @queried << peer.key.data
  end

  def queried?(peer)
    @queried.include?(peer.key.data)
  end
end

class Node
  include Celluloid
  include HasGuardedHandlers
  extend HasGuardedHandlers::ClassMethods
  execute_guarded_handlers_on_receiver

  def self.start(fabric, ip, port)
    key = Key.random
    peer = Peer.new(key, ip, port)
    new(fabric, peer).tap(&:start)
  end

  def initialize(fabric, peer)
    @fabric = fabric
    @peer = peer
    @buckets = Buckets.new(@peer)
  end
  attr_reader :peer, :buckets

  def start
    @fabric.register(ip, port, current_actor)

    register_handler(:message, Message) do |message|
      #puts "adding message source to buckets: #{message.source.key.id.inspect}"
      message.source.contacted!
      @buckets.insert(message.source)

      if message.respond_to?(:peers)
        message.peers.each do |peer|
          @buckets.insert(peer)
        end
      end
      throw :pass
    end

    register_handler(:message, PingRequest) do |message|
      #puts "got ping request: #{message.source.inspect}"
      reply = message.make_reply(@peer)
      send(message.source, reply)
    end

    register_handler(:message, FindNodeRequest) do |message|
      #puts "got find node request: #{message.source.inspect}"
      peers = @buckets.closest_for(message.key)
      reply = message.make_reply(@peer, peers)
      send(message.source, reply)
    end
  end

  def bootstrap(*peers)
    message = PingRequest.new(@peer)
    replies = peers.map do |peer|
      call(peer, message, PingResponse)
    end
    replies.each do |reply|
      #puts "got ping reply"
      reply.source.contacted!
      @buckets.insert(reply.source)
    end
    puts "finding myself"
    current_actor.sync(:find, @peer)
    #puts "finding random keys"
  end

  def find(peer)
    FindNode.new(peer.key, self).run
  end

  def send(peer, message)
    @fabric.async.send(peer.ip, peer.port, Marshal.load(Marshal.dump(message)))
  end

  def call(peer, message, klass)
    send(peer, message)
    register_tmp_handler(:message, klass, :id => message.id) do |reply|
      #puts "got #{klass} from #{reply.source.inspect}"
      signal(message.id, reply)
    end
    wait(message.id)
  end

  def handle(message)
    #p(op: :handle, message: message)
    trigger_handler :message, message
  end

  def ip
    @peer.ip
  end

  def port
    @peer.port
  end

  def inspect
    "#<Node peer=#{@peer.inspect} buckets=#{@buckets.inspect}>"
  end
end

class InMemoryFabric
  include Celluloid

  def initialize
    @nodes = {}
  end

  def register(ip, port, node)
    @nodes["#{ip}:#{port}"] = node
  end

  def send(ip, port, message)
    #p(ip: ip, port: port, message: message)
    node = @nodes.values.find do |n|
      n.ip == ip && n.port == port
    end
    node.async.handle(message)
  end

  def inspect
    "#<Fabric nodes=#{@nodes.size}>"
  end
end
