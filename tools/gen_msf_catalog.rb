#!/usr/bin/env ruby
# -*- coding: binary -*-
# One-shot generator: loads the MSF framework once and emits vendored bytes
# for every single (stageless) native x86/x64/arm64 payload across all OSes,
# every x86/x64 encoder's real decoder stub, and the x86 egghunter stubs.
# Output: JSON array to ARGV[0].
#
# Run with the framework's own Ruby, e.g.:
#   /opt/metasploit-framework/embedded/bin/ruby tools/gen_msf_catalog.rb out.json
FRAMEWORK = ENV['MSF_FRAMEWORK'] || '/opt/metasploit-framework/embedded/framework'
$:.unshift(File.join(FRAMEWORK, 'lib'))
require 'json'
require 'msfenv'
require 'msf/base'
require 'msf/core/payload_generator'
require 'msf/core/constants'
require 'rex/exploitation/egghunter'

OUT = ARGV[0] or abort "usage: gen_msf_catalog.rb OUT.json"
$stderr.sync = true
$stderr.puts "[*] creating framework (loads all modules once)..."
framework = Msf::Simple::Framework.create('DisableDatabase' => true, 'DisableLogging' => true)
$stderr.puts "[*] framework ready: #{framework.stats.num_payloads} payloads, #{framework.stats.num_encoders} encoders"

ARCH_MAP = { 'x86' => 'x86', 'x86_64' => 'x64', 'x64' => 'x64', 'aarch64' => 'arm64' }
# longest / most-specific first so 'x86' doesn't shadow 'x86_64'
ARCH_ORDER = ['x86_64', 'x64', 'aarch64', 'x86']
SIZE_CAP = 8192  # safety net; classic single payloads are a few hundred bytes

def arch_key(archs)
  ARCH_ORDER.each { |a| return ARCH_MAP[a] if archs.include?(a) }
  nil
end

def cmd_for(os)
  os == 'windows' ? 'cmd.exe' : '/bin/sh'
end

# Extract ordered (mnemonic, comment) anchors from a module's source. Handles
# both module styles: asm heredocs ("  mov eax,0x5    ; open() syscall") and
# byte-string payloads ('"\xb0\x66"   #   mov al,0x66 (sys_socketcall)'). The
# mnemonic lets us align these onto our disassembly later; dynamic blocks with
# no per-line comment (e.g. a string-push loop) simply contribute no anchor.
def extract_comments(path)
  return [] unless path && File.file?(path)
  src = (File.read(path) rescue nil) or return []
  body = (m = src.match(/def generate\b.*?\n(.*)\n\s*end\b/m)) ? m[1] : src
  out = []
  body.each_line do |ln|
    if ln =~ /^\s*[a-zA-Z][\w.]*\b[^;"]*;\s*(\S.*?)\s*$/   # asm line ; comment
      comment = $1
      mnem = ln.strip[/^[a-zA-Z][\w.]*/]
      out << [mnem.downcase, comment] if mnem
    elsif ln =~ /"(?:\\x[0-9a-fA-F]{2})+"/ && ln =~ /#\s*(\S.*?)\s*$/  # bytes # comment
      comment = $1
      mnem = comment[/^[a-zA-Z][\w.]*/]
      out << [mnem.downcase, comment] if mnem
    end
  end
  out
end

def fill_datastore(mod, os)
  common = {
    'LHOST' => '127.0.0.1', 'LPORT' => 4444, 'RHOST' => '127.0.0.1', 'RPORT' => 4444,
    'CMD' => cmd_for(os), 'SHELL' => cmd_for(os), 'FILE' => '/etc/passwd',
    'PATH' => '/etc/passwd', 'DIR' => '/tmp', 'URL' => 'http://127.0.0.1/',
    'USER' => 'root', 'PASS' => 'password', 'TIME' => 1, 'SIGNAL' => 9, 'PID' => 1,
  }
  common.each { |k, v| mod.datastore[k] = v if mod.options.include?(k) }
  # Generic fill for anything still required and unset.
  mod.options.each_pair do |name, opt|
    next unless opt.required
    cur = mod.datastore[name]
    next if cur && !cur.to_s.empty?
    mod.datastore[name] =
      case opt
      when Msf::OptPort    then 4444
      when Msf::OptAddress then '127.0.0.1'
      when Msf::OptInt     then 1
      when Msf::OptBool    then false
      when Msf::OptPath    then '/etc/passwd'
      else 'test'
      end
  end
end

entries = []
pay_ok = pay_skip = 0

framework.payloads.each_module do |name, _|
  begin
    next if name =~ /meterpreter|mettle|vncinject|dllinject|dns_txt|reflective/i
    mod = framework.payloads.create(name)
    next if mod.nil?
    next unless mod.payload_type == Msf::Payload::Type::Single
    key = arch_key(mod.arch)
    next if key.nil?
    os = name.split('/').first
    fill_datastore(mod, os)
    raw = mod.generate_simple('Format' => 'raw')
    next if raw.nil? || raw.empty?
    if raw.length > SIZE_CAP
      $stderr.puts "[-] skip (too big #{raw.length}b) #{name}"; pay_skip += 1; next
    end
    entries << {
      'kind' => 'payload', 'refname' => name, 'os' => os, 'arch' => key,
      'name' => mod.name.to_s, 'desc' => mod.description.to_s.split.join(' '),
      'hex' => raw.unpack1('H*'), 'comments' => extract_comments(mod.file_path),
    }
    pay_ok += 1
    $stderr.puts "[+] payload #{name} (#{key}/#{os}) #{raw.length}b"
  rescue ::Interrupt
    raise
  rescue ::Exception => e
    pay_skip += 1
    $stderr.puts "[-] payload #{name} failed: #{e.class}: #{e.message}"
  end
end

$stderr.puts "[*] payloads: #{pay_ok} ok, #{pay_skip} skipped"

# Encoders: generate each x86/x64 encoder's real decoder stub by encoding the
# matching exec payload. Skip shikata_ga_nai (per request). Alphanumeric
# encoders need a BufferRegister pointing at the stub: ECX (x86) / RCX (x64).
BASE = { 'x86' => 'linux/x86/exec', 'x64' => 'linux/x64/exec' }
enc_ok = enc_skip = 0

framework.encoders.each_module do |name, _|
  begin
    next if name =~ /shikata_ga_nai/
    enc = framework.encoders.create(name)
    next if enc.nil?
    key = arch_key(enc.arch)
    next if key.nil?
    pmod = framework.payloads.create(BASE[key])
    pmod.datastore['CMD'] = '/bin/sh'
    pmod.datastore['BufferRegister'] = (key == 'x64' ? 'RCX' : 'ECX') if name =~ /alpha/
    raw = pmod.generate_simple('Format' => 'raw', 'Encoder' => name, 'Iterations' => 1)
    next if raw.nil? || raw.empty?
    if raw.length > SIZE_CAP
      $stderr.puts "[-] skip encoder (too big #{raw.length}b) #{name}"; enc_skip += 1; next
    end
    entries << {
      'kind' => 'decoder', 'refname' => name, 'os' => 'linux', 'arch' => key,
      'name' => enc.name.to_s, 'desc' => enc.description.to_s.split.join(' '),
      'hex' => raw.unpack1('H*'), 'comments' => extract_comments(enc.file_path),
    }
    enc_ok += 1
    $stderr.puts "[+] encoder #{name} (#{key}) #{raw.length}b"
  rescue ::Interrupt
    raise
  rescue ::Exception => e
    enc_skip += 1
    $stderr.puts "[-] encoder #{name} failed: #{e.class}: #{e.message}"
  end
end

$stderr.puts "[*] encoders: #{enc_ok} ok, #{enc_skip} skipped"

# Egghunters: Rex::Exploitation::Egghunter generates a small stub that scans
# memory for a doubled 4-byte tag and jumps to the payload after it. The
# framework only ships x86 stubs, for Linux and Windows. We use the classic
# 'w00t' tag; edit it in the editor to match the tag prefixed to your payload.
egg_ok = 0
[['linux', 'linux'], ['windows', 'win']].each do |os, plat|
  begin
    eh = Rex::Exploitation::Egghunter.new(plat, Rex::Arch::ARCH_X86)
    hunter, _egg = eh.generate("\xcc".b, '', { :eggtag => 'w00t' })
    next if hunter.nil? || hunter.empty?
    entries << {
      'kind' => 'egghunter', 'refname' => "#{os}/x86/egghunter", 'os' => os, 'arch' => 'x86',
      'name' => "#{os.capitalize} x86 egghunter (tag 'w00t')",
      'desc' => "Scans memory for the doubled 4-byte tag 'w00tw00t' and jumps " \
                "to the payload that follows it.",
      'hex' => hunter.unpack1('H*'),
    }
    egg_ok += 1
    $stderr.puts "[+] egghunter #{os}/x86 #{hunter.length}b"
  rescue ::Exception => e
    $stderr.puts "[-] egghunter #{os} failed: #{e.class}: #{e.message}"
  end
end
$stderr.puts "[*] egghunters: #{egg_ok} ok"

File.write(OUT, JSON.pretty_generate(entries))
$stderr.puts "[*] wrote #{entries.length} entries to #{OUT}"
