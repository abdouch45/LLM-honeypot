import argparse
from twisted.internet import reactor
from twisted.protocols.basic import LineReceiver
from twisted.internet.protocol import Factory


class FakeFTP(LineReceiver):
    delimiter = b"\r\n"

    def connectionMade(self):
        peer = self.transport.getPeer()
        print(f"[ftp-server] connection from {peer.host}:{peer.port}")
        self.sendLine(b"220 FakeFTP Service Ready")
        self.logged_in = False

    def lineReceived(self, line: bytes) -> None:
        text = line.decode("utf-8", errors="replace")
        command, _, args = text.partition(" ")
        command = command.upper()
        print(f"[ftp-server] received: {text}")

        if command == "USER":
            self.sendLine(b"331 Username OK, need password")
        elif command == "PASS":
            self.logged_in = True
            self.sendLine(b"230 Login successful")
        elif command == "SYST":
            self.sendLine(b"215 UNIX Type: L8")
        elif command == "PWD":
            self.sendLine(b"257 \"/\" is current directory")
        elif command == "CWD":
            self.sendLine(b"250 Directory changed")
        elif command == "LIST":
            self.sendLine(b"150 Opening ASCII mode data connection for file list")
            self.sendLine(b"226 Transfer complete")
        elif command == "QUIT":
            self.sendLine(b"221 Goodbye")
            self.transport.loseConnection()
        else:
            self.sendLine(b"502 Command not implemented")


def start_ftp_server(port: int = 2121):
    factory = Factory()
    factory.protocol = FakeFTP
    reactor.listenTCP(port, factory)
    print(f"[ftp-server] listening on 0.0.0.0:{port}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Start the fake FTP honeypot server.")
    parser.add_argument("-p", "--port", type=int, default=2121, help="TCP port for FTP server")
    args = parser.parse_args()
    start_ftp_server(args.port)
    reactor.run()


if __name__ == "__main__":
    main()
