require 'spec_helper'

RSpec.describe RubySMB::Client do

  let(:dispatcher) { RubySMB::Dispatcher::Socket.new(nil) }
  subject(:client) { described_class.new(dispatcher) }
  subject(:smb1_client) { described_class.new(dispatcher, smb2:false) }
  subject(:smb2_client) { described_class.new(dispatcher, smb1:false) }

  describe '#initialize' do
    it 'should raise an ArgumentError without a valid dispatcher' do
      expect{ described_class.new(nil) }.to raise_error(ArgumentError)
    end

    it 'defaults to true for SMB1 support' do
      expect(client.smb1).to be true
    end

    it 'defaults to true for SMB2 support' do
      expect(client.smb1).to be true
    end

    it 'accepts an argument to disable smb1 support' do
      smb_client = described_class.new(dispatcher, smb1:false)
      expect(smb_client.smb1).to be false
    end

    it 'accepts an argument to disable smb2 support' do
      expect(smb1_client.smb2).to be false
    end
  end

  describe '#smb1_negotiate_request' do
    it 'returns a SMB1 Negotiate Request packet' do
      expect(client.smb1_negotiate_request).to be_a(RubySMB::SMB1::Packet::NegotiateRequest)
    end

    it 'sets the default SMB1 Dialect' do
      expect(client.smb1_negotiate_request.dialects).to include({:buffer_format=>2, :dialect_string=> RubySMB::Client::SMB1_DIALECT_SMB1_DEFAULT})
    end

    it 'sets the SMB2.02 dialect if SMB2 support is enabled' do
      expect(client.smb1_negotiate_request.dialects).to include({:buffer_format=>2, :dialect_string=> RubySMB::Client::SMB1_DIALECT_SMB2_DEFAULT})
    end

    it 'excludes the SMB2.02 Dialect if SMB2 support is disabled' do
      expect(smb1_client.smb1_negotiate_request.dialects).to_not include({:buffer_format=>2, :dialect_string=> RubySMB::Client::SMB1_DIALECT_SMB2_DEFAULT})
    end

    it 'excludes the default SMB1 Dialect if SMB1 support is disabled' do
      expect(smb2_client.smb1_negotiate_request.dialects).to_not include({:buffer_format=>2, :dialect_string=> RubySMB::Client::SMB1_DIALECT_SMB1_DEFAULT})
    end
  end

end