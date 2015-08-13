module RubySMB
  module SMB1
    module Packet
      module NegotiateCommand

        # Represents a SMB1 Negotiate request packet.
        # [2.2.4.52.1 Request](https://msdn.microsoft.com/en-us/library/ee441572.aspx)
        class Request < BinData::Record
          RubySMB::SMB1::Packet::SMBHeader
          RubySMB::SMB1::Packet::SMBDataBlock
          RubySMB::SMB1::Packet::SMBParameterBlock
          RubySMB::SMB1::Packet::NegotiateCommand::Dialect

          smb_header :smb_header
          smb_parameter_block :smb_parameter_block
          smb_data_block :smb_data_block

          def build
            smb_header.protocol = RubySMB::SMB1::SMB_PROTOCOL_ID
            smb_header.command = RubySMB::SMB1::COMMANDS[:SMB_COM_NEGOTIATE]
            self
          end

          def set_dialects(dialects=[])
            dialects_block = BinData::Array.new(:type => :dialect)
            dialects_block.assign(dialects)
            smb_data_block.bytes = dialects_block.to_binary_s
            self
          end

          def self.parse(string_input)
            smb_header = RubySMB::SMB1::Packet::SMBHeader.read(string_input[RubySMB::SMB1::Packet::SMBHeader::SMB_HEADER_BYTES])

            parameter_word_count = BinData::Bit8.read(string_input[RubySMB::SMB1::Packet::SMBParameterBlock::SMB_PARAMETER_BLOCK_OFFSET]).to_i * 2 + RubySMB::SMB1::Packet::SMBParameterBlock::SMB_PARAMETER_WORD_COUNT
            smb_parameter_block = RubySMB::SMB1::Packet::SMBParameterBlock.read(string_input[RubySMB::SMB1::Packet::SMBParameterBlock::SMB_PARAMETER_BLOCK_OFFSET, parameter_word_count])

            data_byte_size = BinData::Bit16le.read(string_input[RubySMB::SMB1::Packet::SMBParameterBlock::SMB_PARAMETER_BLOCK_OFFSET + parameter_word_count, RubySMB::SMB1::Packet::SMBDataBlock::SMB_DATA_BYTE_SIZE])
            smb_data_block = RubySMB::SMB1::Packet::SMBDataBlock.read(string_input[RubySMB::SMB1::Packet::SMBParameterBlock::SMB_PARAMETER_BLOCK_OFFSET + parameter_word_count, data_byte_size + RubySMB::SMB1::Packet::SMBDataBlock::SMB_DATA_BYTE_SIZE])
            self.new(:smb_header => smb_header, :smb_parameter_block => smb_parameter_block, :smb_data_block => smb_data_block)
          end
        end
      end
    end
  end
end