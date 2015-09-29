module RubySMB
module SMB1
module Command
class  NegotiateRequest < RubySMB::Field::Composite

  def initialize
    super()

    add_child( RubySMB::Field::LeafField.new(
                    name: :protocol,
                 n_bytes_allocated: 4,
                   value: "\xFFSMB"
               ))

    add_child(RubySMB::Field::LeafField.new(
                   name: :command,
                   n_bytes_allocated: 1,
                  value: "\x72"
              ))

    add_child(RubySMB::Field::LeafField.new(
                   name: :status,
                   n_bytes_allocated: 4,
                  value: "\x00"
              ))

    add_child( RubySMB::Field::LeafField.new(
                   name: :flags,
                   n_bytes_allocated: 1,
                  value: "\x18"
               ))

    add_child( RubySMB::Field::LeafField.new(
                   name: :flags2,
                   n_bytes_allocated: 2,
                  value: "\x48\x01"
               ))

    add_child( RubySMB::Field::LeafField.new(
                   name: :pid_high,
                   n_bytes_allocated: 2,
                  value: "\x00"
               ))

    add_child( RubySMB::Field::LeafField.new(
                   name: :security_features,
                   n_bytes_allocated: 8,
                  value: "\x00"
               ))

    add_child( RubySMB::Field::LeafField.new(
                   name: :reserved,
                   n_bytes_allocated: 2,
                  value: "\x00"
               ))

    add_child( RubySMB::Field::LeafField.new(
                   name: :tid,
                   n_bytes_allocated: 2,
                  value: "\xFF\xFF"
               ))

    add_child( RubySMB::Field::LeafField.new(
                   name: :pid_low,
                   n_bytes_allocated: 2,
                  value: "\x00"
               ))

    add_child( RubySMB::Field::LeafField.new(
                   name: :uid,
                   n_bytes_allocated: 2,
                  value: "\x00"
               ))

    add_child( RubySMB::Field::LeafField.new(
                   name: :mid,
                   n_bytes_allocated: 2,
                  value: "\x00"
               ))

    add_child( RubySMB::Field::LeafField.new(
                   name: :dialects,
                   n_bytes_allocated: 34,
                  value: "\x02NT LM 0.12\x00\x02SMB 2.002\x00\x02SMB 2.???\x00"
               ))



    # add_child( RubySMB::Field::LeafField.new do |f|
    #              f.name         = :dialects
    #              f.n_bytes_allocated = 34
    #              f.dialects = RubySMB::Field::Composite_Field.new do |d|
    #                  d.add_child(RubySMB::Field::LeafField.new do |df|
    #                   df.name   = :d1
    #                   df.n_bytes_allocated = 12
    #                   df.value  = "\x02NT LM 0.12\x00"
    #                  end)
    #
    #                  d.add_child()
    #
    #
    #
    #              f.value        = "\x02NT LM 0.12\x00\x02SMB 2.002\x00\x02SMB 2.???\x00"
    #            end )


  end

  def build

  end

  def field(name)
    puts self.inspect
    children.select { |f| f.name == name }.first
  end

end
end
end
end
