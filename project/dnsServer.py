import os
import time
import dnslib
import dnslib.label
import dnslib.server

# used https://github.com/CryptoPunk/tlsmy.net/blob/master/server/dnsserver.py as a reference
class Resolver(object):
    def __init__(self, domains, server_ip, raw_domains):
        self.domains = domains
        self.raw_domains = raw_domains
        self.server_ip = server_ip
        self.txt = {}

    def resolve(self, request, handler):
        reply = request.reply()
        qname = request.q.qname

        # dnslib.RCODE refused if wrong doman
        # if (qname != self.domain):
        #     reply.header.rcode = dnslib.RCODE.REFUSED
        #     return reply

        # QTYPE A queries
        if request.q.qtype == dnslib.QTYPE.A:
            reply.add_answer(dnslib.RR(qname, dnslib.QTYPE.A, ttl=300, rdata=self.server_ip))
            return reply


        # subdomain = qname._decode(qname.label[1]).lower()
        first_domain_part = qname._decode(qname.label[0]).lower()
        # index = []

        second_domain_part = ''
        for i in range(len(qname.label)):
            if i == 0:
                continue
            elif i == 1:
                second_domain_part += qname._decode(qname.label[i]).lower()
            else:
                second_domain_part +=  '.'+qname._decode(qname.label[i]).lower()
        # print(second_domain_part)

        # for i in range(len(self.raw_domains)):
        #     if  (second_domain_part == self.raw_domains[i] or '*.'+second_domain_part == self.raw_domains[i]):
        #         index.append(i)
        # print(self.domains)
        # print(index)
        # print("DNS request: ", index)
        # print("result: ", self.txt[index])

        if (first_domain_part == '_acme-challenge' and request.q.qtype == dnslib.QTYPE.TXT):
            try:
                reply.add_answer(dnslib.RR(qname, dnslib.QTYPE.TXT, ttl=300, rdata=dnslib.TXT(self.txt[second_domain_part])));
                reply.add_answer(dnslib.RR(qname, dnslib.QTYPE.TXT, ttl=300, rdata=dnslib.TXT(self.txt['*.'+second_domain_part])));
            except KeyError:
                pass
            return reply

        reply.header.rcode = dnslib.RCODE.NXDOMAIN
        return reply

def setup_resolver(ip, domains):
    # domain = dnslib.label('_acme-challenge.'+dom)
    doms = [dnslib.label('_acme-challenge.'+dom) for dom in domains]
    resolver = Resolver(doms, dnslib.A(ip), domains)
    return resolver


def run_server(resolver, ip):
    port=10053
    logger = dnslib.server.DNSLogger("pass")
    udp_server = dnslib.server.DNSServer(resolver, address=ip, port=port, logger=logger)
    print('starting DNS server on port', port)
    udp_server.start_thread()
    return udp_server

# resolver = setup_resolver('127.0.0.1', ["example.com", "*.example.com"])
# udp_server = run_server(resolver, '127.0.0.1')
# resolver.txt[0] = "hello"
# resolver.txt[1] = "test"
#
# try:
#     while udp_server.isAlive():
#         time.sleep(1)
# except KeyboardInterrupt:
#     pass
