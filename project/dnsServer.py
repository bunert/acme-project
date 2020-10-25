import os
import time
import dnslib
import dnslib.label
import dnslib.server

# used https://github.com/CryptoPunk/tlsmy.net/blob/master/server/dnsserver.py as a reference
class Resolver(object):
    def __init__(self, domain, server_ip):
        self.domain = domain
        self.server_ip = server_ip
        self.txt = ''

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

        if (first_domain_part == '_acme-challenge' and request.q.qtype == dnslib.QTYPE.TXT and self.txt != ''):
            reply.add_answer(dnslib.RR(qname, dnslib.QTYPE.TXT, ttl=300, rdata=dnslib.TXT(self.txt)));
            return reply

        reply.header.rcode = dnslib.RCODE.NXDOMAIN
        return reply

def setup_resolver(ip, dom):
    domain = dnslib.label('_acme-challenge.'+dom)

    resolver = Resolver(domain, dnslib.A(ip))
    return resolver


def run_server(resolver, ip):
    port=10053
    logger = dnslib.server.DNSLogger("pass")
    udp_server = dnslib.server.DNSServer(resolver, address=ip, port=port, logger=logger)
    print('starting DNS server on port', port)
    udp_server.start_thread()
    return udp_server


# if __name__ == '__main__':
#
#     # domain = dnslib.label('www.example.com')
#     domain = dnslib.label('_acme-challenge.www.example.com')
#     logger = dnslib.server.DNSLogger("pass")
#     port=10053
#     resolver = Resolver(domain, dnslib.A('1.2.3.4'))
#     udp_server = dnslib.server.DNSServer(resolver, address='127.0.0.1', port=port, logger=logger)
#
#     print('starting DNS server on port', port)
#     udp_server.start_thread()
#
#     try:
#         while udp_server.isAlive():
#             time.sleep(1)
#     except KeyboardInterrupt:
#         pass
