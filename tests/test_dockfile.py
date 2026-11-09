"""The Dockerfile reader: line numbers, continuations, heredocs, flags."""

from __future__ import annotations

from docklint.dockfile import (
    image_tag,
    is_json_form,
    parse_copy_args,
    parse_dockerfile,
    shell_split,
)


def test_line_numbers_survive_comments_and_blanks():
    text = "# syntax=docker/dockerfile:1.6\n\nFROM alpine:3.19\n# a note\nRUN echo hi\n"
    df = parse_dockerfile(text)
    assert [i.name for i in df.instructions()] == ["RUN"]
    assert df.instructions()[0].line == 5
    assert df.stages[0].line == 3


def test_leading_whitespace_is_tolerated():
    df = parse_dockerfile("  FROM alpine:3.19\n\tRUN echo hi\n")
    assert df.stages[0].image == "alpine:3.19"
    assert df.stages[0].instructions[0].name == "RUN"


def test_continuation_joins_into_one_instruction():
    text = "FROM alpine:3.19\nRUN apt-get update \\\n    && apt-get install -y curl\n"
    df = parse_dockerfile(text)
    run = df.stages[0].instructions[0]
    assert "apt-get install" in run.args
    assert run.line == 2
    assert run.end_line == 3


def test_comment_inside_continuation_does_not_end_it():
    text = "FROM alpine:3.19\nRUN echo a \\\n# explain\n    && echo b\n"
    df = parse_dockerfile(text)
    run = df.stages[0].instructions[0]
    assert "echo b" in run.args
    assert run.end_line == 4


def test_heredoc_body_is_not_parsed_as_instructions():
    text = (
        "FROM alpine:3.19\n"
        "RUN <<EOF\n"
        "FROM this-is-not-a-stage\n"
        "echo done\n"
        "EOF\n"
        "CMD [\"sh\"]\n"
    )
    df = parse_dockerfile(text)
    assert len(df.stages) == 1
    assert [i.name for i in df.stages[0].instructions] == ["RUN", "CMD"]
    assert df.stages[0].instructions[0].heredocs[0].word == "EOF"


def test_copy_heredoc_is_captured():
    text = "FROM alpine:3.19\nCOPY <<'CONF' /etc/app.conf\nkey=value\nCONF\n"
    df = parse_dockerfile(text)
    copy = df.stages[0].instructions[0]
    assert copy.name == "COPY"
    assert copy.heredocs[0].body == "key=value"
    assert copy.args.startswith("<<'CONF'")


def test_from_platform_flag_is_not_mistaken_for_a_tag():
    df = parse_dockerfile("FROM --platform=linux/amd64 node:20 AS build\n")
    assert df.stages[0].image == "node:20"
    assert df.stages[0].alias == "build"


def test_alias_case_is_preserved_but_matched_case_insensitively():
    df = parse_dockerfile("FROM alpine:3.19 AS Builder\nFROM Builder\n")
    assert df.stages[0].alias == "Builder"
    assert df.stages[1].image == "Builder"


def test_instructions_before_the_first_from_go_to_the_preamble():
    df = parse_dockerfile("ARG BASE=alpine:3.19\nFROM ${BASE}\n")
    assert [i.name for i in df.preamble] == ["ARG"]
    assert df.stages[0].instructions == []


def test_escape_directive_is_honoured():
    text = "# escape=`\nFROM alpine:3.19\nRUN echo a `\n    && echo b\n"
    df = parse_dockerfile(text)
    assert df.escape == "`"
    assert "echo b" in df.stages[0].instructions[0].args


def test_syntax_directive_is_recorded():
    df = parse_dockerfile("# syntax=docker/dockerfile:1.6\nFROM alpine:3.19\n")
    assert df.syntax == "docker/dockerfile:1.6"


def test_garbage_line_is_reported_not_crashed():
    df = parse_dockerfile("FROM alpine:3.19\nthis is not an instruction\n")
    assert df.errors and "line 2" in df.errors[0]
    assert len(df.stages) == 1


def test_snippet_returns_the_original_line():
    df = parse_dockerfile("FROM alpine:3.19\nRUN echo hi\n")
    assert df.snippet(2) == "RUN echo hi"
    assert df.snippet(99) == ""


def test_snippet_is_truncated_with_an_ellipsis():
    long = "RUN " + "x" * 200
    df = parse_dockerfile(f"FROM alpine:3.19\n{long}\n")
    out = df.snippet(2, width=40)
    assert len(out) == 40 and out.endswith("\u2026")


def test_stage_of_line_attributes_correctly():
    df = parse_dockerfile("FROM a:1 AS one\nRUN x\nFROM b:2 AS two\nRUN y\n")
    assert df.stage_of_line(2) == "one"
    assert df.stage_of_line(4) == "two"


def test_final_stage_is_the_last_from():
    df = parse_dockerfile("FROM a:1\nFROM b:2\n")
    assert df.final_stage().image == "b:2"


def test_image_tag_variants():
    assert image_tag("nginx") == ""
    assert image_tag("nginx:1.25") == "1.25"
    assert image_tag("ghcr.io/org/app:2.0") == "2.0"
    assert image_tag("registry.local:5000/app") == ""
    assert image_tag("nginx@sha256:" + "a" * 64) == ""


def test_shell_split_respects_quotes():
    assert shell_split('"a b.txt" /dst') == ["a b.txt", "/dst"]
    assert shell_split("a b c") == ["a", "b", "c"]


def test_json_form_detection():
    assert is_json_form('["python", "-m", "http.server"]')
    assert not is_json_form("python -m http.server")
    assert not is_json_form("[not json")


def test_copy_args_flags_and_json_form():
    flags, parts = parse_copy_args('--from=build --chown=1000:1000 ["a", "b", "/dst"]')
    assert flags["from"] == "build"
    assert flags["chown"] == "1000:1000"
    assert parts == ["a", "b", "/dst"]


def test_copy_args_shell_form_keeps_quoted_paths():
    flags, parts = parse_copy_args("--chmod=755 \"my file.txt\" /dst")
    assert flags["chmod"] == "755"
    assert parts == ["my file.txt", "/dst"]


def test_copy_args_without_destination_still_returns_sources():
    flags, parts = parse_copy_args("/app")
    assert flags == {}
    assert parts == ["/app"]


def test_instruction_flags_helper():
    df = parse_dockerfile("FROM alpine:3.19\nCOPY --from=build --link /a /b\n")
    copy = df.stages[0].instructions[0]
    assert copy.flags() == {"from": "build", "link": ""}
    assert copy.without_flags() == "/a /b"


def test_crlf_input_is_normalised():
    df = parse_dockerfile("FROM alpine:3.19\r\nRUN echo hi\r\n")
    assert df.stages[0].image == "alpine:3.19"
    assert df.stages[0].instructions[0].args == "echo hi"
