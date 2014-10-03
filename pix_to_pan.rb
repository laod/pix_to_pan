#!/usr/bin/ruby

require 'treetop'
require 'ipaddr'

# todo: handle non-directional acls like those for bogons
# todo: Inside needs to be a list of IPAddrs (subnet 208)
# todo: consider expanding inside concept to multiple zones

# monkeypatch courtesy of: http://stackoverflow.com/questions/19305586/convert-from-ipaddr-to-netaddrcidr-type/24259011#24259011
class IPAddr
  def prefix
    begin_addr = (@addr & @mask_addr)

    case @family
      when Socket::AF_INET
        end_addr = (@addr | (IN4MASK ^ @mask_addr))
      when Socket::AF_INET6
        end_addr = (@addr | (IN6MASK ^ @mask_addr))
      end

    32 - Math.log(end_addr - begin_addr + 1, 2).to_i
  end

  def to_cidr_s
    to_s + "/#{prefix}"
  end

  def to_pan_name
    to_cidr_s.gsub('.','_').gsub('/','-')
  end
end

def safer_access
  begin
    yield
  rescue
    nil
  end
end

def maybe(i)
  if i
    if i.respond_to?(:empty?)
      i.empty? ? nil : yield(i)
    else
      yield i
    end
  else
    nil
  end
end


class Acl
  attr_accessor :tree, :name, :src, :sport, :dest, :dport, :action, :protocol, :direction, :groups, :service
  Inside = IPAddr.new '129.244.0.0/16'
  def self.parts
    [:name,:action,:protocol,:src,:sport,:dest,:dport]
  end
  def ip(node)
    safer_access{node.addr.ip.text_value}
  end
  def mask(node)
    safer_access{node.addr.mask.text_value}
  end
  def baseport
    maybe(safer_access{yield}){|i| services["#{i} #{@protocol}"]}
  end
  def bot(node)
    baseport {node.sp.portspec.bot.text_value}
  end
  def top(node)
    baseport {node.sp.portspec.top.text_value}
  end
  def port(node)
    baseport {node.sp.portspec.port.text_value}
  end
  def services
    @@services ||= File.new('/etc/services').readlines
                                      .reject{|l| l.start_with? '#'}
                                      .reject{|l| /^ *$/ =~ l}
                                      .map{|l| /^(.+?)(#.*)?$/.match(l)[1]}
                                      .reduce(Hash.new{|h,k| k.split.first}){|h,l| t = l.split; (port, proto) = t[1].split('/'); [t[0],t[2..-1]].flatten.compact.reduce(h){|m,i| m["#{i} #{proto}"] = port; m}}
                                      .merge({"lpd tcp" => "515"})
  end
  def initialize(parsetree)
    @tree = parsetree
    @name = @tree.name.text_value
    @src = maybe([ip(@tree.src),mask(@tree.src)].compact){|i| IPAddr.new(i.join('/'))} || IPAddr.new("0.0.0.0/0")
    @dest = maybe([ip(@tree.dest),mask(@tree.dest)].compact){|i| IPAddr.new(i.join('/'))} || IPAddr.new("0.0.0.0/0")
    @protocol = @tree.protocol.protocol.text_value
    @sport = maybe(bot(@tree.src)){|i| i+'-'+top(@tree.src)} || port(@tree.src) || 'any_port'
    @dport = maybe(bot(@tree.dest)){|i| i+'-'+top(@tree.dest)} || port(@tree.dest) || 'any_port'
    @action = @tree.action.text_value
    @direction = (src_inside? || !dest_inside?) ? 'out' : 'in'
    @groups = []
    @service = Service.get_service(self)
  end

  def inspect
    a = [name, src.to_pan_name, sport, dest.to_pan_name, dport, action, protocol, direction]
    a.join(' ')
  end

  def src_inside?
    @src && Inside.include?(@src)
  end

  def dest_inside?
    @dest && Inside.include?(@dest)
  end

  def relevant_address
    direction == 'in' ? dest : src
  end

  def port_policy?
    src.to_cidr_s == '0.0.0.0/0' && dest.to_cidr_s == '0.0.0.0/0'
  end

  def get_parts(parts)
    parts.map{|p| send(p)}
  end

  def choose_group
    groups.sort{|g| g.acls.count}.last
  end

  #todo: fix this horrible shit (next three methods)
  def get_part_strings(parts)
    parts.zip(get_parts(parts)).map{|k,v| [:src,:dest].include?(k) ? v.to_cidr_s : v}
  end

  def name_part(part)
    g = choose_group
    pt = send(part)
    case
      when g && g.what == part
        "these #{part}s"
      when [:src, :dest].include?(part)
        pt.to_cidr_s == '0.0.0.0/0' ? '' : pt.to_pan_name
      when part.to_s.end_with?('port')
        pt == 'any_port' ? '' : pt
      else
        part
    end
  end

  def human_readable
    s = [:src,:sport].map{|pt| name_part(pt)}.reject{|p| p == ''}
    d = [:dest,:dport].map{|pt| name_part(pt)}.reject{|p| p == ''}
    h = "#{name} #{action} #{protocol}"
    h += " from #{s.join(" ")}" unless s.empty?
    h += " to #{d.join(" ")}" unless d.empty?
    h
  end
end

class AclGroup
  attr_accessor :acls,:what
  def initialize(what,acls,gs)
    @what = what
    @acls = acls
    @acls.each{|a| a.groups<<self}
    @emitted = false
    @gs = gs
  end

  def emitted?
    @emitted
  end

  def emit
    @emitted = true
    to_s
  end
end

class AclGroups
  attr_accessor :acls,:groups
  def initialize
    @acls = []
    @groups = {}
  end

  def <<(acl)
    @acls << acl
  end

  def addresses
    @acls.map{|i| [i.src, i.dest]}.flatten.compact.uniq
  end

  def services
    @acls.map{|i| Service.get_service i}.compact.uniq
  end

  def group(what)
    @acls.select{|a| block_given? ? yield(a) : true}.group_by{|acl| acl.get_part_strings(Acl.parts - [what]).join(" ")}.reject{|g,m| m.count <= 1}.map{|g,m| AclGroup.new(what,m,g)}
  end

  def src_groups
    @groups[:srces] = group :src
  end

  def dest_groups
    @groups[:dests] = group :dest
  end

  def sport_groups
    @groups[:sports] = group(:sport){|acl| acl.port_policy?}
  end

  def dport_groups
    @groups[:dports] = group(:dport){|acl| acl.port_policy?}
  end

  def port_groups
    sport_groups + dport_groups
  end

  def self.p_groups(groups)
    puts groups.map{|group,members| "#{group} ->\n\t#{members.map{|acl| acl.inspect}.join("\n\t")}"}.join("\n======\n")
  end

  def used_groups
    acls.map{|a| a.choose_group}.compact.uniq
  end
end

class Service
  @@services = {}
  attr_accessor :protocol, :sport, :dport, :pan_name
  def initialize
  end
  def self.get_service(acl)
    return nil if acl.sport == 'any_port' && acl.dport == 'any_port'
    pan_name = "#{acl.protocol} #{acl.sport} #{acl.dport}"
    @@services[pan_name] ||= new.tap do |o|
      [:protocol,:sport,:dport].each{|p| o.instance_variable_set("@#{p}",acl.send(p))}
      o.instance_variable_set("@pan_name",pan_name)
    end
  end
  def to_xml
    <<XML
<entry name="#{pan_name}">
  <protocol>
    <#{protocol}>
    <port>#{dport != 'any_port' ? dport : '1-65535'}</port>#{"\n\t\t<source-port>#{sport}</source-port>" unless sport == 'any_port'}
    </#{protocol}>
  </protocol>
</entry>
XML
  end
end

Treetop.load 'pix'
parser = PixParser.new

#WARNING: the grammar is incomplete and this invocation eats
# parse failures. Instrument.
acls = AclGroups.new
ARGF.map{|i| parser.parse(i.strip)}
    .compact
    .each{|i| acls << Acl.new(i)}

acls.dest_groups
acls.src_groups
acls.dport_groups
acls.sport_groups

#puts acls.groups.map{|k,v| "#{k}->\n#{v}"}.join("\n\n")
#acls.acls.each{|a| puts "#{a.inspect} [#{a.choose_group}]"}

addresses = acls.addresses
address_groups = acls.used_groups.select{|g| [:src,:dest].include? g.what}

puts "Addresses"
addresses.each{|a| puts "<entry name=\"#{a.to_pan_name}\"><ip-netmask>#{a.to_cidr_s}</ip-netmask></entry>"}

# If using named groups:
#
#puts "Address Groups"
#puts address_groups.map{|group| <<XML
#<entry name="#{group}">
#  #{group.acls.map{|acl| acl.get_parts([group.what]).first}.map{|addr| "<member>#{addr.to_pan_name}</member>"}.join("\n\t")}
#</entry>
#
#XML
#}

puts "Services"
puts acls.services.map{|s| s.to_xml}.join

# Named group src/dest template
# <member>#{(g && g.what == :src) ? g.emit : a.src.to_pan_name}</member>

# Rule names may only be 31 characters on the pa. So much for:
#<entry name="#{a.human_readable}">

puts "Policies\n\n"
acls.acls.each_with_index do |a,i|
  g = a.choose_group
  next if (g && g.emitted?)
puts <<XML
<entry name="#{a.name}_#{sprintf("%03d",i)}">
  <option>
    <disable-server-response-inspection>no</disable-server-response-inspection>
  </option>
  <from>
    <member>#{a.direction == 'in' ? 'untrust' : 'trust'}</member>
  </from>
  <to>
    <member>#{a.direction == 'in' ? 'trust' : 'untrust'}</member>
  </to>
  <source>
    #{(g && g.what == :src) ? g.tap{|o| o.instance_eval("@emitted = true")}.acls.map{|aa| "<member>#{aa.src.to_pan_name}</member>"}.join("\n") : "<member>#{a.src.to_pan_name}</member>"}
  </source>
  <destination>
    #{(g && g.what == :dest) ? g.tap{|o| o.instance_eval("@emitted = true")}.acls.map{|aa| "<member>#{aa.dest.to_pan_name}</member>"}.join("\n") : "<member>#{a.dest.to_pan_name}</member>"}
  </destination>
  <source-user>
    <member>any</member>
  </source-user>
  <category>
    <member>any</member>
  </category>
  <application>
    <member>any</member>
  </application>
  <service>
    #{(g && g.what.to_s.end_with?("port")) ? g.tap{|o| o.instance_eval("@emitted = true")}.acls.map{|aa| "<member>#{aa.service.pan_name}</member>"}.join("\n") : "<member>#{maybe(a.service){|o| o.pan_name} || "any"}</member>"}
  </service>
  <hip-profiles>
    <member>any</member>
  </hip-profiles>
  <action>allow</action>
  <log-start>no</log-start>
  <log-end>yes</log-end>
  <negate-source>no</negate-source>
  <negate-destination>no</negate-destination>
</entry>
XML
end
