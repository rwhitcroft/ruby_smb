module RubySMB
  module SMB1
    module Packet

      # Namespace for all packets and structures related to the the SMB1
      # Negotiate command.
      module NegotiateCommand
        autoload :Dialect, 'ruby_smb/smb1/packet/negotiate_command/dialect'
        autoload :Request, 'ruby_smb/smb1/packet/negotiate_command/request'
      end
    end
  end
end