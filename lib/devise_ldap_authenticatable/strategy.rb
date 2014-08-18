require 'devise/strategies/authenticatable'

module Devise
  module Strategies
    class LdapAuthenticatable < Authenticatable
      def authenticate!
        resource = mapping.to.find_for_ldap_authentication(authentication_hash.merge(password: password))

        if resource && validate(resource) { resource.valid_ldap_authentication?(password) }
          resource.after_ldap_authentication
          success!(resource)
        elsif ::Devise.ldap_database_authenticatable_fallback
          resource  = valid_password? && mapping.to.find_for_database_authentication(authentication_hash)
          encrypted = false

          if validate(resource){ encrypted = true; resource.valid_password?(password) }
            resource.after_database_authentication
            success!(resource)
          end

          mapping.to.new.password = password if !encrypted && Devise.paranoid
          fail(:not_found_in_database) unless resource
        else
          return fail(:invalid)
        end
      end
    end
  end
end

Warden::Strategies.add(:ldap_authenticatable, Devise::Strategies::LdapAuthenticatable)
