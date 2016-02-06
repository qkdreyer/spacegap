require_relative 'spacegap'
require_relative 'parser'
args = Parser.parse({devices: {}, directory: Dir.home + '/certificates/'})

if !args.id
	abort "Missing Unique Identifier"
end

spacegap = Spacegap.new(args)
app = spacegap.handle_application
spacegap.handle_keys
