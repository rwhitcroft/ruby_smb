require 'spec_helper'

module RubySMB
module SMB1
module Command
RSpec.describe NegotiateRequest do
  context 'SMB Specification - Packet Structure & Defaults' do
    let(:command) { NegotiateRequest.new }

    describe '#field(:protocol)' do
      let(:field) { command.field(:protocol) }

      it 'has name :protocol' do
        expect(field.name).to eql :protocol
      end

      it 'has n_bytes_spec = 4' do
        expect(field.n_bytes_spec).to eql 4
      end

      it 'has default value = "\\xFFSMB"' do
        expect(field.value).to eql "\xFFSMB"
      end
    end

    describe '#field(:command)' do
      let(:field) { command.field(:command) }

      it 'has name :command' do
        expect(field.name).to eql :command
      end

      it 'has n_bytes_spec = 1' do
        expect(field.n_bytes_spec).to eql 1
      end

      it 'has default value = "\x72"' do
        expect(field.value).to eql "\x72"
      end
    end

    describe '#field(:status)' do
      let(:field) { command.field(:status) }

      it 'has name :status' do
        expect(field.name).to eql :status
      end

      it 'has n_bytes_spec = 4' do
        expect(field.n_bytes_spec).to eql 4
      end

      it 'has default value = "\x00"' do
        expect(field.value).to eql "\x00"
      end
    end

    describe '#field(:flags)' do
      let(:field) { command.field(:flags) }

      it 'has name :flags' do
        expect(field.name).to eql :flags
      end

      it 'has n_bytes_spec = 1' do
        expect(field.n_bytes_spec).to eql 1
      end

      it 'has default value = "\x18"' do
        expect(field.value).to eql "\x18"
      end
    end

    describe '#field(:flags2)' do
      let(:field) { command.field(:flags2) }

      it 'has name :flags2' do
        expect(field.name).to eql :flags2
      end

      it 'has n_bytes_spec = 2' do
        expect(field.n_bytes_spec).to eql 2
      end

      it 'has default value = "\x48\x01"' do
        expect(field.value).to eql "\x48\x01"
      end
    end

    describe '#field(:pid_high)' do
      let(:field) { command.field(:pid_high) }

      it 'has name :pid_high' do
        expect(field.name).to eql :pid_high
      end

      it 'has n_bytes_spec = 2' do
        expect(field.n_bytes_spec).to eql 2
      end

      it 'has default value = "\x00"' do
        expect(field.value).to eql "\x00"
      end
    end

    describe '#field(:security_features)' do
      let(:field) { command.field(:security_features) }

      it 'has name :security_features' do
        expect(field.name).to eql :security_features
      end

      it 'has n_bytes_spec = 8' do
        expect(field.n_bytes_spec).to eql 8
      end

      it 'has default value = "\x00"' do
        expect(field.value).to eql "\x00"
      end
    end

    describe '#field(:reserved)' do
      let(:field) { command.field(:reserved) }

      it 'has name :reserved' do
        expect(field.name).to eql :reserved
      end

      it 'has n_bytes_spec = 2' do
        expect(field.n_bytes_spec).to eql 2
      end

      it 'has default value = "\x00"' do
        expect(field.value).to eql "\x00"
      end
    end

    describe '#field(:tid)' do
      let(:field) { command.field(:tid) }

      it 'has name :tid' do
        expect(field.name).to eql :tid
      end

      it 'has n_bytes_spec = 2' do
        expect(field.n_bytes_spec).to eql 2
      end

      it 'has default value = "\xFF\xFF"' do
        expect(field.value).to eql "\xFF\xFF"
      end
    end

    describe '#field(:pid_low)' do
      let(:field) { command.field(:pid_low) }

      it 'has name :pid_low' do
        expect(field.name).to eql :pid_low
      end

      it 'has n_bytes_spec = 2' do
        expect(field.n_bytes_spec).to eql 2
      end

      it 'has default value = "\x00"' do
        expect(field.value).to eql "\x00"
      end
    end

    describe '#field(:uid)' do
      let(:field) { command.field(:uid) }

      it 'has name :uid' do
        expect(field.name).to eql :uid
      end

      it 'has n_bytes_spec = 2' do
        expect(field.n_bytes_spec).to eql 2
      end

      it 'has default value = "\x00"' do
        expect(field.value).to eql "\x00"
      end
    end

    describe '#field(:mid)' do
      let(:field) { command.field(:mid) }

      it 'has name :mid' do
        expect(field.name).to eql :mid
      end

      it 'has n_bytes_spec = 2' do
        expect(field.n_bytes_spec).to eql 2
      end

      it 'has default value = "\x00"' do
        expect(field.value).to eql "\x00"
      end
    end

    describe '#field(:dialects)' do
      let(:field) { command.field(:dialects) }

      it 'has name :dialects' do
        expect(field.name).to eql :dialects
      end

      it 'has n_bytes_spec = 34' do
        expect(field.n_bytes_spec).to eql 34
      end

      it 'has default value = dialect string' do
        expect(field.value).to eql "\x02NT LM 0.12\x00\x02SMB 2.002\x00\x02SMB 2.???\x00"
      end
    end

  end



  it 'default values'

  it 'dialects attr'
  it '#add_dialect'
end
end
end
end
