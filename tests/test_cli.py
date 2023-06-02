from spfmerge.spfmerge import cli

def test_cli(capsys):
    args = [
        "v=spf1 a a:one.one.one.one include:one.one.one.one ip4:1.1.1.1 ~all",
        "v=spf1 mx ip6:2606:4700:4700::1111 -all"
    ]
    cli(args)
    captured = capsys.readouterr()
    result = captured.out
    assert "v=spf1" in result
