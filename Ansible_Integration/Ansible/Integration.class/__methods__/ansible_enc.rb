#
# Author: Chris Ruffalo <cruffalo@redhat.com>
#
# Description: Prepares to run a playbook by encrypting target values
# Inputs:
#   enc_params: a list of params to extract from the root/object and encrypt with 'password::' prefix
# Outputs:
#   values starting with enc_ corresponding to each enc_param on the object and root
#
module Ansible_Integration
  module Ansible
    class Integration

      require 'miq-password'

      def initialize(handle = $evm)
        @handle = handle
      end

      def get_key(key)
        value = @handle.inputs[key] if !@handle.inputs.nil? && !@handle.inputs[key].nil?
        value = @handle.object[key] if !@handle.object.nil? && value.nil? && !@handle.object[key].nil?
        value = @handle.root[key] if !@handle.root.nil? && value.nil? && !@handle.root[key].nil?
        return value
      end

      def main
        enc_prefix = get_key('enc_prefix')
                
        # extract requested encrypted variables
        vault_params = get_key('enc_params') or Array.new
        vault_params.each do |param_name| 
          # go to next if param_name is nil or empty
          next if param_name.nil? or param_name.empty?

          # get param and continue/next if param is null
          param_value = get_key(param_name) or nil
          next if param_value.nil?

          # enc value should start as empty
          enc_value = ''

          # decrypt the value and use that and keep common rencryption (do not log this!)
          # if the value is nil there is no value returned and we can ignore it
          dec_value = @handle.object.decrypt(param_name) or @handle.root.decrypt(param_name) or nil
          param_value = dec_value unless dec_value.nil?
          
          # determine encrypted value, empty values cannot be encrypted and
          # encrypted values will not be re-encrypted
          if !param_value.nil? and !param_value.empty?
            # create ansible-encrypted string which needs too have "password::" in front of it so that the manageiq-automate 
            # code sees it as an encrypted password because this is what cloudforms will do out of the box
            enc_value =  "password::#{MiqPassword.new.encrypt(param_value)}"
          end

          # **always** store as '#{enc_prefix}#{param_name}' on object and root
          @handle.root["#{enc_prefix}#{param_name}"] = enc_value
          @handle.object["#{enc_prefix}#{param_name}"] = enc_value
        end

      end

    end 
  end
end

if __FILE__ == $PROGRAM_NAME
  Ansible_Integration::Ansible::Integration.new.main
end
