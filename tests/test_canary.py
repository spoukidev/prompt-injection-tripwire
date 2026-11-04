from hypothesis import given, strategies as st

from tripwire import canary


def test_roundtrip_zero_width():
    tok = canary.new_token()
    enc = canary.encode_zero_width(tok)
    assert all(c in "\u200b\u200c\u2063\u2064" for c in enc)
    assert [h.token for h in canary.find_tokens("abc" + enc + "def")] == [tok]


def test_visible_form():
    tok = canary.new_token()
    assert canary.find_tokens(f"x {canary.render(tok, visible=True)} y")[0].token == tok


def test_plant_keeps_html_tags_intact_and_repeats():
    tok = canary.new_token()
    html = "<p class='a b c'>" + "word " * 200 + "</p>"
    out = canary.plant(html, tok, every=50)
    assert len(canary.find_tokens(out)) > 5
    # no canary inside a tag
    for h in canary.find_tokens(out):
        before = out[: h.start]
        assert before.count("<") == before.count(">")
    assert canary.strip_tokens(out) == html


def test_excerpt_carries_canary():
    tok = canary.new_token()
    out = canary.plant("First sentence here. " * 30, tok, every=40)
    assert any(h.token == tok for h in canary.find_tokens(out[100:300]))


def test_strip_truncated_canary_fragment():
    tok = canary.new_token()
    enc = canary.encode_zero_width(tok)
    assert canary.strip_tokens("hello " + enc[:20]) == "hello "


@given(st.text(max_size=300))
def test_plant_then_strip_is_identity(text):
    tok = canary.new_token()
    assert canary.strip_tokens(canary.plant(text, tok)) == text or any(c in text for c in "\u200b\u200c\u2063\u2064")
    assert any(h.token == tok for h in canary.find_tokens(canary.plant(text, tok)))
