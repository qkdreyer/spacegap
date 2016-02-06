require 'spaceship'
require 'phonegap-api'
require 'openssl'
require 'httmultiparty'

class Spacegap < Spaceship::Base

    def initialize(args)
        @email = args.email
        @password = args.password
        @id = args.id
        @passphrase = args.passphrase
        @devices = args.devices
        @repository = args.repository
        @uninstall = !!args.uninstall
        @path = args.directory + args.id
        @key = args.key || @name.downcase

        chunks = args.id.split('.')
        @country = chunks[0]
        @company = chunks[1]
        @name = chunks[2]

        @pgb = Phonegap::ConnectionToken.new(args.token, self.handle_signing_keys)
    end

    def handle_application
        app = @pgb.apps.instance_variable_get("@apps").detect { |app| app.instance_variable_get("@package") == @id }

        if !app && !@uninstall
            app = Phonegap::App.new(@pgb.create_app(:title => true, :repo => handle_repository, :create_method => 'remote_repo'))
        elsif app && @uninstall
            @pgb.delete_app(app.instance_variable_get("@id"))
        end

        return app
    end

    def handle_repository(username = '', password = '')
        if @repository.include? "http://git.triotech.fr"
            @repository.sub(Regexp.escape("(http://)(git.triotech.fr/.*)"), "$1#{username}:#{password}$2")
        end
        return @repository
    end

    def handle_keys
        keys = {}
        @pgb.keys["keys"].each do |platform, data|
            key = data["all"].detect { |key| key["title"] == @id }
            if platform === "ios"
                if !key
                    key = @pgb.add_key(@id, platform)
                end
                puts key["id"]

                keys[platform] = key
            end
        end

        @pgb.unlock(keys, @key)
    end

    def handle_signing_keys
        p12 = self.handle_p12(true)
        mobileprovision = self.handle_mobileprovision(true)

        if !p12 || !mobileprovision
            if !@email
                abort "Missing User Email"
            elsif !@password
                abort "Missing User Password"
            end

            @spaceship = Spaceship.login(@email, @password)
            team = self.handle_team
            app = self.handle_app
            devices = self.handle_devices
            p12 = self.handle_p12
            mobileprovision = self.handle_mobileprovision
        end

        return {'p12' => p12, 'mobileprovision' => mobileprovision}
    end

    def handle_team(teams = [])
        team = nil
        teams = @spaceship.teams

        if teams && teams.count > 1
            team = teams.detect { |t| t['name'].downcase == @company }
            if team
                id = team['teamId']
                puts "Using Team #{id}"
                @spaceship.team_id = id
            else
                abort "Unable to find team for #{@id}"
            end
        else
            puts "No team registered"
        end

        return team
    end

    def handle_app
        app = Spaceship.app.find(@id)

        if !app && !@uninstall
            puts "Creating Application #{id}"
            app = Spaceship.app.create!(bundle_id: @id, name: @name)
        elsif app && @uninstall
            puts "Uninstalling Application #{id}"
            app.delete!
        else
            puts "Using Application #{app.bundle_id}"
        end

        return app
    end

    def handle_devices
        @devices.each do |udid, name|
            device = Spaceship.device.find_by_udid(udid)
            if !device
                puts "Creating Device (#{name})"
                Spaceship.device.create!(name: name, udid: udid)
            end
        end

        return Spaceship.device.all
    end

    def handle_p12(check = false, extension = 'p12')
        p12_file = self.handle_file(@path, extension)
        return p12_file if check

        if !p12_file && !@uninstall
            begin
                cer_file = self.handle_cer
                pem_file = self.handle_file(drop_part(@path), 'pem')
                pkey = OpenSSL::PKey.read(pem_file, @passphrase)
                cert = OpenSSL::X509::Certificate.new(cer_file)
                p12 = OpenSSL::PKCS12::create(@key, @id, pkey, cert).to_der
                p12_file = self.handle_file(@path, extension, p12)
            rescue ArgumentError
                abort "Invalid Private Key Passphrase"
            end
        elsif p12_file && @uninstall
            p12_file = self.handle_file(@path, extension, -1)
        end

        return p12_file
    end

    def handle_cer(extension = 'cer')
        cer_file = self.handle_file(@path, extension)

        if !cer_file && !@uninstall
            cer = self.handle_certificate
            cer_file = self.handle_file(@path, extension, cer.download.to_pem)
        elsif cer_file && @uninstall
            cer_file = self.handle_file(@path, extension, -1)
        end

        if cer && DateTime.parse(cer.expires.to_s).prev_month < Date.today
            puts "Renewing Certificiate"
            #TODO
        end

        return cer_file
    end

    def handle_certificate
        cert = Spaceship.certificate.production.all.first

        if !cert && !@uninstall
            puts "Creating CSR, Private Key, and Certificate"
            csr, pkey = Spaceship.certificate.create_certificate_signing_request
            cert = Spaceship.certificate.production.create!(csr: csr)

            if passphrase
                pkey = pkey.to_pem(OpenSSL::Cipher::AES192.new(:CBC), @passphrase)
            else
                pkey = pkey.to_pem
            end

            self.handle_file(drop_part(@path), 'pem', pkey) # removes project from id
        elsif cert && @uninstall
            #cert.revoke!
        end

        return cert
    end

    def handle_mobileprovision(check = false, extension = 'mobileprovision')
        mobileprovision_file = self.handle_file(@path, extension)
        return mobileprovision_file if check

        if !mobileprovision_file && !@uninstall
            profile = self.handle_profile
            mobileprovision_file = self.handle_file(@path, extension, profile.download)
        elsif mobileprovision_file && @uninstall
            mobileprovision_file = self.handle_file(@path, extension, -1)
        end

        return mobileprovision_file
    end

    def handle_profile
        profile = Spaceship.provisioning_profile.ad_hoc.find_by_bundle_id(@id).first

        if !profile && !@uninstall
            puts "Creating AdHoc Provisioning Profile"
            cert = self.handle_certificate
            profile = Spaceship.provisioning_profile.ad_hoc.create!(bundle_id: @id, certificate: cert, name: "#{name} AdHoc")
        elsif profile && @uninstall
            used_profiles = Spaceship.provisioning_profile.all.reject { |p| p.id == profile.id }
            used_devices = used_profiles.map { |p| p.devices }.flatten.map { |d| d.id }.uniq
            unused_devices = profile.devices.reject { |d| used_devices.include? d.id }.each do |device|
                puts "Disabing Device (#{device.name})"
                device.disable!
            end
            puts "Deleting AdHoc Provisioning Profile"
            profile.delete!
        end

        return profile
    end

    def handle_file(filepath, extension, bytes = nil)
        file = "#{filepath}.#{extension}"

        if bytes.is_a?(Fixnum) && bytes == -1
            puts "Deleting #{file}"
            File.delete(file)
        elsif bytes.is_a?(String) && bytes.length > 0
            puts "Writing to #{file} > #{bytes.length} bytes"
            File.write(file, bytes)
        end

        return File.exists?(file) ? File.new(file) : nil
    end

    def drop_part(txt, sep = '.', drop = 1)
        txt.split(sep).reverse.drop(drop).reverse.join(sep)
    end
end

module Spaceship
    module Portal
        class Device
            def disable!
                #TODO
            end
        end
    end
end

module Phonegap
    class ConnectionToken < Connection
        include HTTMultiParty
        base_uri 'https://build.phonegap.com/api/v1'

        def initialize(token, signing_keys)
            @token = "?auth_token=#{token}"
            @auth = {}

            @p12 = signing_keys['p12']
            @mobileprovision = signing_keys['mobileprovision']
            @keystore = signing_keys['keystore']
        end

        def multipart_body(body, query = {})
            return @auth.merge!({:body => {:data => body}.merge(query)})
        end

        def get(url)
            super url + @token
        end

        def delete(url)
            super url + @token, body
        end

        def post(url, body, query = {})
            output = self.class.post(url + @token, multipart_body(body, query))
            check_response!(output).parsed_response
        end

        def put(url, body, query = {})
            output = self.class.put(url + @token, multipart_body(body, query))
            check_response!(output).parsed_response
        end

        def unlock(keys, password)
            if keys["ios"]
                id = keys["ios"]["id"]
                ios = self.put("/keys/ios/#{id}", {"password" => password})
                puts 'ios', ios, password
            elsif keys["android"]
                id = keys["android"]["id"]
                android = self.put("/keys/android/#{id}", {"key_pw" => password, "keystore_pw" => password})
                puts 'android', android
            end
        end

        def build(id, pull = true)
            self.post("/apps/#{id}", {"pull" => pull});
        end

        def add_key(title, platform, password = nil)
            query = {}
            keys = {"title" => title}
            if platform == "ios"
                query["cert"] = @p12
                query["profile"] = @mobileprovision
                keys["password"] = password if password
            elsif platform == "android"
                query["keystore"] = @keystore
                keys["alias"] = title
                keys["key_pw"] = keys["keystore_pw"] = password if password
            elsif platform == "winphone"
                keys["publisher_id"] = ""
            end

            self.post("/keys/#{platform}", keys, query)
        end
    end
end

module HTTParty
    class Request
        def http
            connection_adapter.call(uri, options.merge({:verify => false}))
        end
    end
end
