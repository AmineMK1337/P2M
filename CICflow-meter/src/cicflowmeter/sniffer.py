import sys
from scapy.sendrecv import AsyncSniffer
from cicflowmeter.flow_session import FlowSession


def run(input_file, output_file):
    session = FlowSession(
        output_mode="csv",
        output=output_file,
        fields=None,
        verbose=False,
    )

    sniffer = AsyncSniffer(
        offline=input_file,
        prn=session.process,
        store=False,
    )

    sniffer.start()
    sniffer.join()

    session.flush_flows()


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python sniffer.py <pcap> <csv>")
        sys.exit(1)

    run(sys.argv[1], sys.argv[2])