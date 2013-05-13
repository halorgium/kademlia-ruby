require_relative "code"

describe Key do
  it "works" do
    expect(Key.new("\xf0\x00").first_set_bit_index).to eq(15)
    expect(Key.new("\x00\x01").first_set_bit_index).to eq(0)
  end

  it "produces randomness" do
    master = Key.random
    threads = 4.times.map do
      key = Key.new(master.data.dup)
      Thread.new(key) do |key2|
        1000000.times.map { Key.random.xor(key2).first_set_bit_index}.uniq.sort
      end
    end
    pp threads.map(&:value).flatten.uniq.sort
  end
end
