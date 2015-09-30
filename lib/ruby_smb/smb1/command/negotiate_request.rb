require 'pry'
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
                   value: "\x48\x34"
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

    #add parameter fields
    add_child( RubySMB::Field::LeafField.new(
                    name: :byte_count,
       n_bytes_allocated: 1,
                   value: "\x00"
               ))

    #add data fields
    add_child( RubySMB::Field::LeafField.new(
                    name: :byte_count,
       n_bytes_allocated: 2,
                   value: "\x00"
               ))

    set_dialects(['NT LM 0.12', 'SMB 2.002', 'SMB 2.???'])
  end

  def build

  end

  def field(name)
    children.select { |f| f.name == name }.first
  end

  def set_dialects(dialects = [])
    self.delete_child(children.select{| field| field.name == 'dialects'}.first)
    dialects_field = RubySMB::Field::Composite.new(name: 'dialects')
    dialects.each_with_index do |dialect, index|
      dialect_field = RubySMB::Field::Composite.new(name: "dialect#{index}")
      dialect_field.add_child(
        RubySMB::Field::LeafField.new(
                            name: 'buffer_format',
               n_bytes_allocated: 1,
                           value: "\x02"
      ))
      dialect_field.add_child(
        RubySMB::Field::LeafField.new(
                            name: 'dialect_string',
                           value: dialect
      ))
      dialect_field.add_child(
        RubySMB::Field::LeafField.new(
                            name: 'null',
               n_bytes_allocated: 1,
                           value: "\x00"
      ))

      dialects_field.add_child(dialect_field)
    end

    byte_count_value = [dialects_field.to_binary_s.bytesize.to_s(16).to_i].pack('c*')

    children.select{ |child| child.name == :byte_count }.first.value = byte_count_value
    self.add_child(dialects_field)
  end
end
end
end
end
