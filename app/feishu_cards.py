"""Lossless card segmentation using serialized UTF-8 size, not character counts."""

from copy import deepcopy
import json

CARD_BYTES = 28000  # Headroom below Feishu's 30 KB message limit.


class MessageID(str):
    def __new__(cls, value, parts=()):
        result = super().__new__(cls, value)
        result.message_ids = tuple(parts) or (str(value),)
        return result


def message_ids(value):
    return getattr(value, "message_ids", ()) or ((str(value),) if value else ())


def wire_size(card):
    payload = {
        "receive_id": "x" * 128,
        "msg_type": "interactive",
        "reply_in_thread": False,
        "content": json.dumps(card, ensure_ascii=False),
    }
    return len(json.dumps(payload, ensure_ascii=False).encode("utf-8"))


def split_card(card):
    if wire_size(card) <= CARD_BYTES:
        return [card]
    base = deepcopy(card)
    elements = base.pop("elements", [])
    title = base.setdefault("header", {}).setdefault("title", {"tag": "plain_text"})
    original_title = title.get("content", "")
    title["content"] = original_title + "（第 9999/9999 段）"

    def fits(items):
        return wire_size({**base, "elements": items}) <= CARD_BYTES

    sections, current = [], []
    for element in elements:
        if fits(current + [element]):
            current.append(element)
            continue
        if current:
            sections.append(current)
            current = []
        if fits([element]):
            current.append(element)
            continue
        text = element.get("text")
        if (
            element.get("tag") != "div"
            or not isinstance(text, dict)
            or not isinstance(text.get("content"), str)
        ):
            raise ValueError("飞书卡片的非文本组件超过容量，内容未截断")
        remaining = text["content"]
        while remaining:
            lo, hi = 0, len(remaining)
            while lo < hi:
                mid = (lo + hi + 1) // 2
                piece = {**element, "text": {**text, "content": remaining[:mid]}}
                if fits([piece]):
                    lo = mid
                else:
                    hi = mid - 1
            if not lo:
                raise ValueError("飞书卡片结构超过容量，内容未截断")
            if lo < len(remaining):
                newline = remaining.rfind("\n", 0, lo)
                if newline >= lo // 2:
                    lo = newline + 1
            piece = {**element, "text": {**text, "content": remaining[:lo]}}
            remaining = remaining[lo:]
            if remaining:
                sections.append([piece])
            else:
                current = [piece]
    if current:
        sections.append(current)
    result = []
    for index, section in enumerate(sections, 1):
        part = deepcopy(base)
        part["header"]["title"]["content"] = (
            f"{original_title}（第 {index}/{len(sections)} 段）"
        )
        part["elements"] = section
        result.append(part)
    return result
