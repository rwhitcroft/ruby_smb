module RubySMB
module SMB1
module Command
class  NegotiateRequest < RubySMB::SMB_Field::Composite_Field

  def initialize
    super()

    add_field( RubySMB::SMB_Field::Leaf_Field.new do |f|
                 f.name         = :protocol
                 f.n_bytes_spec = 4
                 f.value        = "\xFFSMB"
               end )

    add_field( RubySMB::SMB_Field::Leaf_Field.new do |f|
                 f.name         = :command
                 f.n_bytes_spec = 1
                 f.value        = "\x72"
               end )

    add_field( RubySMB::SMB_Field::Leaf_Field.new do |f|
                 f.name         = :status
                 f.n_bytes_spec = 4
                 f.value        = "\x00"
               end )

    add_field( RubySMB::SMB_Field::Leaf_Field.new do |f|
                 f.name         = :flags
                 f.n_bytes_spec = 1
                 f.value        = "\x18"
               end )

    add_field( RubySMB::SMB_Field::Leaf_Field.new do |f|
                 f.name         = :flags2
                 f.n_bytes_spec = 2
                 f.value        = "\x48\x01"
               end )

    add_field( RubySMB::SMB_Field::Leaf_Field.new do |f|
                 f.name         = :pid_high
                 f.n_bytes_spec = 2
                 f.value        = "\x00"
               end )

    add_field( RubySMB::SMB_Field::Leaf_Field.new do |f|
                 f.name         = :security_features
                 f.n_bytes_spec = 8
                 f.value        = "\x00"
               end )

    add_field( RubySMB::SMB_Field::Leaf_Field.new do |f|
                 f.name         = :reserved
                 f.n_bytes_spec = 2
                 f.value        = "\x00"
               end )

    add_field( RubySMB::SMB_Field::Leaf_Field.new do |f|
                 f.name         = :tid
                 f.n_bytes_spec = 2
                 f.value        = "\xFF\xFF"
               end )

    add_field( RubySMB::SMB_Field::Leaf_Field.new do |f|
                 f.name         = :pid_low
                 f.n_bytes_spec = 2
                 f.value        = "\x00"
               end )

    add_field( RubySMB::SMB_Field::Leaf_Field.new do |f|
                 f.name         = :uid
                 f.n_bytes_spec = 2
                 f.value        = "\x00"
               end )

    add_field( RubySMB::SMB_Field::Leaf_Field.new do |f|
                 f.name         = :mid
                 f.n_bytes_spec = 2
                 f.value        = "\x00"
               end )

    add_field( RubySMB::SMB_Field::Leaf_Field.new do |f|
                 f.name         = :dialects
                 f.n_bytes_spec = 34
                 f.value        = "\x02NT LM 0.12\x00\x02SMB 2.002\x00\x02SMB 2.???\x00"
               end )



    # add_field( RubySMB::SMB_Field::Leaf_Field.new do |f|
    #              f.name         = :dialects
    #              f.n_bytes_spec = 34
    #              f.dialects = RubySMB::SMB_Field::Composite_Field.new do |d|
    #                  d.add_field(RubySMB::SMB_Field::Leaf_Field.new do |df|
    #                   df.name   = :d1
    #                   df.n_bytes_spec = 12
    #                   df.value  = "\x02NT LM 0.12\x00"
    #                  end)
    #
    #                  d.add_field()
    #
    #
    #
    #              f.value        = "\x02NT LM 0.12\x00\x02SMB 2.002\x00\x02SMB 2.???\x00"
    #            end )


  end

  def build

  end

  def field(name)
    fields.select { |f| f.name == name }.first
  end

end
end
end
end
