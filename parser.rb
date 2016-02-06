require 'optparse'
require 'ostruct'

class Parser
	def self.parse(args = {})
		OptionParser.new do |opts|
			opts.banner = "Usage: example.rb [options]"

			opts.on("-e", "--email EMAIL", "Apple ID User Email") do |email|
				args[:email] = email
			end

			opts.on("-p", "--password PASSWORD", "Apple ID User Password") do |password|
				args[:password] = password
			end

			opts.on("-k", "--key KEY", "Certificate Export Key") do |key|
				args[:key] = key
			end

			opts.on("-z", "--passphrase PASSPHRASE", "Private Key Passphrase") do |passphrase|
				args[:passphrase] = passphrase
			end

			opts.on("-i", "--id ID", "Unique Identifier") do |id|
				if id.split('.').count != 3
					abort "Invalid Unique Identifier. (Format: country.company.project)"
				end
				args[:id] = id
			end

			opts.on("-t", "--token TOKEN", "PhoneGapBuild API Token") do |token|
				args[:token] = token
			end

			opts.on("-r", "--repository REPOSITORY", "Application Git Repository") do |repository|
				args[:repository] = repository
			end

			opts.on("-o", "--output-directory", "Output Directory") do |directory|
				if !directory.end_with?('/')
					directory += '/'
				end
				args[:directory]
			end

			opts.on("-d", "--devices DEVICE", "Authorized Devices (name1:id1;name2:id2") do |devices|
				devices.split(';').each do |device|
					data = device.split(':')
					name = data[0]
					udid = data[1]
					args[:devices][udid] = name
				end
			end

			opts.on("-u", "--uninstall", "Uninstall application, provisioning profile, and dedicated devices") do |u|
				args[:uninstall] = u
			end
		end.parse!

		OpenStruct.new(args)
	end
end
