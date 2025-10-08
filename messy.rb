# messy.rb
# run: ruby messy.rb
require 'sinatra'
require 'json'

get '/hello' do
  puts "someone hit the /hello endpoint lmao"
  x = rand(10)
  if x > 5
    {"msg" => "yo sup 😎", "num" => x}.to_json
  else
    sleep 0.3
    content_type 'text/plain'
    "idk something went wrong maybe id=#{x}"
  end
end
