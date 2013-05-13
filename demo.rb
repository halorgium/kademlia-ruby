require_relative "code"

binding.pry

fabric = InMemoryFabric.new

master = Node.start(fabric, "127.0.0.1", 4000)
p master
nodes = 300.times.map do |i|
  node = Node.start(fabric, "127.0.0.1", 5000 + i)
  p node
end

bootstrapping = nodes.map do |node|
  node.future.bootstrap(master)
end

bootstrapping.map(&:value)

p master.buckets.peer_count
p nodes.map(&:buckets).map(&:peer_count).sort

binding.pry
