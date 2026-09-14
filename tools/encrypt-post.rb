#!/usr/bin/env ruby
# frozen_string_literal: true
#
# Encrypt a post for the client-side "protected post" feature.
#
# Usage:
#   ruby tools/encrypt-post.rb path/to/content.md
#   (the password is asked interactively and hidden — it never touches the
#    shell history, the repo, or the output)
#
# It renders the Markdown to HTML (kramdown + rouge, like Jekyll), encrypts it
# with AES-256-GCM using a key derived from the password (PBKDF2-SHA256), and
# prints a <div class="post-lock" ...> block. Paste that block as the BODY of a
# post whose front matter has `protected: true`. The plaintext never ships and
# the password is NEVER stored — only salt + iv + ciphertext go into the post.
#
# IMPORTANT: keep the plaintext source (content.md) OUT of the repo. Put it in
# secret-src/ (git-ignored) or outside the project, and never commit it.
#
# NOTE: this folder is excluded from the Jekyll build (see _config.yml).

require 'openssl'
require 'base64'
require 'securerandom'
require 'io/console'
require 'kramdown'
begin
  require 'rouge'
rescue LoadError
end

ITER = 200_000

md_path = ARGV[0]

abort "Usage: ruby tools/encrypt-post.rb <content.md>" if md_path.nil?
abort "File not found: #{md_path}" unless File.exist?(md_path)

# Ask for the password interactively (hidden) so it never lands in shell history.
password = ARGV[1]
if password.nil?
  password = $stdin.getpass('Password: ')
  confirm = $stdin.getpass('Confirm : ')
  abort 'Passwords do not match.' unless password == confirm
else
  warn 'WARNING: passing the password as an argument leaves it in your shell history. Prefer running without it.'
end
abort 'Empty password.' if password.nil? || password.empty?

markdown = File.read(md_path)

html = Kramdown::Document.new(
  markdown,
  syntax_highlighter: 'rouge',
  syntax_highlighter_opts: { css_class: 'highlight' }
).to_html

salt = SecureRandom.random_bytes(16)
iv   = SecureRandom.random_bytes(12)

key = OpenSSL::PKCS5.pbkdf2_hmac(password, salt, ITER, 32, OpenSSL::Digest::SHA256.new)

cipher = OpenSSL::Cipher.new('aes-256-gcm')
cipher.encrypt
cipher.key = key
cipher.iv = iv
ciphertext = cipher.update(html) + cipher.final
tag = cipher.auth_tag # 16 bytes
payload = ciphertext + tag # WebCrypto expects ciphertext||tag

b64 = ->(bytes) { Base64.strict_encode64(bytes) }

puts
puts "Paste this as the body of the protected post (front matter: protected: true):"
puts "----------------------------------------------------------------------------"
puts %Q{<div class="post-lock" data-iter="#{ITER}" data-salt="#{b64.call(salt)}" data-iv="#{b64.call(iv)}" data-cipher="#{b64.call(payload)}"></div>}
puts "----------------------------------------------------------------------------"
puts
