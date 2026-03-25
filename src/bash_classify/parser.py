"""Bash expression parser using tree-sitter-bash."""

from __future__ import annotations

import tree_sitter
import tree_sitter_bash

from .models import CommandInvocation, Redirect

_parser = tree_sitter.Parser()
_parser.language = tree_sitter.Language(tree_sitter_bash.language())


def parse_expression(expression: str) -> tuple[list[CommandInvocation], list[str]]:
    """Parse a bash expression into a list of CommandInvocation objects.

    Uses tree-sitter-bash to parse the expression into a CST,
    then walks the tree to extract command invocations.

    Returns:
        A tuple of (invocations, parse_warnings).
    """
    tree = _parser.parse(expression.encode())
    warnings: list[str] = []
    if tree.root_node.has_error:
        warnings.append(f"tree-sitter reported a syntax error in expression: {expression!r}")
    invocations = _walk_node(tree.root_node, context="toplevel", operator_before=None)
    return invocations, warnings


def _walk_node(
    node: tree_sitter.Node,
    *,
    context: str,
    operator_before: str | None,
    pipeline_position: int = 0,
    pipeline_length: int = 1,
) -> list[CommandInvocation]:
    """Recursively walk a tree-sitter node and extract command invocations."""
    results: list[CommandInvocation] = []

    if node.type == "program":
        results.extend(_walk_children_as_list(node, context=context))

    elif node.type == "list":
        results.extend(_walk_list_node(node, context=context, operator_before=operator_before))

    elif node.type == "pipeline":
        results.extend(_walk_pipeline_node(node, context=context, operator_before=operator_before))

    elif node.type == "command":
        inv = _extract_command(
            node,
            context=context,
            operator_before=operator_before,
            pipeline_position=pipeline_position,
            pipeline_length=pipeline_length,
        )
        if inv is not None:
            results.append(inv)
        # Also extract nested commands from command arguments (command_substitution, process_substitution)
        results.extend(_extract_nested_from_command_args(node))

    elif node.type == "redirected_statement":
        results.extend(
            _walk_redirected_statement(
                node,
                context=context,
                operator_before=operator_before,
                pipeline_position=pipeline_position,
                pipeline_length=pipeline_length,
            )
        )

    elif node.type == "subshell":
        results.extend(_walk_subshell(node, context="subshell", operator_before=operator_before))

    elif node.type == "command_substitution":
        results.extend(_walk_compound_inner(node, context="command_substitution"))

    elif node.type == "process_substitution":
        results.extend(_walk_compound_inner(node, context="process_substitution"))

    elif node.type == "test_command":
        inv = _extract_test_command(
            node,
            context=context,
            operator_before=operator_before,
            pipeline_position=pipeline_position,
            pipeline_length=pipeline_length,
        )
        if inv is not None:
            results.append(inv)

    elif node.type == "negated_command":
        # Handle `! cmd` — extract the inner command
        for child in node.children:
            if child.type != "!":
                results.extend(
                    _walk_node(
                        child,
                        context=context,
                        operator_before=operator_before,
                        pipeline_position=pipeline_position,
                        pipeline_length=pipeline_length,
                    )
                )

    else:
        # For any other node type, recurse into children
        for child in node.children:
            results.extend(
                _walk_node(
                    child,
                    context=context,
                    operator_before=operator_before,
                    pipeline_position=pipeline_position,
                    pipeline_length=pipeline_length,
                )
            )

    return results


def _walk_children_as_list(
    node: tree_sitter.Node,
    *,
    context: str,
) -> list[CommandInvocation]:
    """Walk children of a program or compound node as a sequence of statements."""
    results: list[CommandInvocation] = []
    operator_before: str | None = None

    for child in node.children:
        if child.type in ("\n", ";", "&", ";;"):
            if child.type == ";":
                operator_before = ";"
            elif child.type == "&":
                # Background operator — mark previous command; next command gets no operator_before from this
                _mark_last_background(results)
                operator_before = None
            continue

        child_results = _walk_node(child, context=context, operator_before=operator_before)
        results.extend(child_results)
        operator_before = None

    return results


def _walk_list_node(
    node: tree_sitter.Node,
    *,
    context: str,
    operator_before: str | None,
) -> list[CommandInvocation]:
    """Walk a 'list' node which connects commands with &&, ||, ;, or &."""
    results: list[CommandInvocation] = []
    current_operator = operator_before

    for child in node.children:
        if child.type in ("&&", "||", ";"):
            current_operator = child.type
            continue
        if child.type == "&":
            _mark_last_background(results)
            current_operator = None
            continue
        if child.type in ("\n",):
            continue

        child_results = _walk_node(child, context=context, operator_before=current_operator)
        results.extend(child_results)
        current_operator = None

    return results


def _walk_pipeline_node(
    node: tree_sitter.Node,
    *,
    context: str,
    operator_before: str | None,
) -> list[CommandInvocation]:
    """Walk a pipeline node, extracting each command with its pipeline position."""
    # Collect command nodes in the pipeline (skip | operators)
    command_nodes = [child for child in node.children if child.type not in ("|", "|&")]
    pipe_len = len(command_nodes)

    results: list[CommandInvocation] = []
    for i, cmd_node in enumerate(command_nodes):
        op = operator_before if i == 0 else None
        child_results = _walk_node(
            cmd_node, context=context, operator_before=op, pipeline_position=i, pipeline_length=pipe_len
        )
        results.extend(child_results)

    return results


def _walk_redirected_statement(
    node: tree_sitter.Node,
    *,
    context: str,
    operator_before: str | None,
    pipeline_position: int,
    pipeline_length: int,
) -> list[CommandInvocation]:
    """Walk a redirected_statement node, extracting the command and its redirects."""
    results: list[CommandInvocation] = []
    redirects = _extract_redirects_from_node(node)

    # The first child is typically the actual command/pipeline/etc
    body_node = None
    for child in node.children:
        if child.type not in ("file_redirect", "heredoc_redirect", "herestring_redirect"):
            body_node = child
            break

    if body_node is None:
        return results

    # Get the commands from the body
    inner = _walk_node(
        body_node,
        context=context,
        operator_before=operator_before,
        pipeline_position=pipeline_position,
        pipeline_length=pipeline_length,
    )

    # Attach redirects only to the first command from the body to avoid duplication
    # (e.g., redirected compound statements like `for ... done > file` should only
    # attach the redirect once, not to every command inside the loop body)
    redirects_attached = False
    for inv in inner:
        if not redirects_attached and inv.position_in_pipeline == pipeline_position:
            if not inv.redirects:
                inv.redirects = redirects
            else:
                inv.redirects.extend(redirects)
            redirects_attached = True

    results.extend(inner)

    # Also extract nested commands from redirect targets (shouldn't normally happen, but be safe)
    return results


def _walk_subshell(
    node: tree_sitter.Node,
    *,
    context: str,
    operator_before: str | None,
) -> list[CommandInvocation]:
    """Walk a subshell node — inner commands get context='subshell'."""
    results: list[CommandInvocation] = []
    for child in node.children:
        if child.type in ("(", ")"):
            continue
        results.extend(_walk_node(child, context=context, operator_before=operator_before))
        operator_before = None
    return results


def _walk_compound_inner(
    node: tree_sitter.Node,
    *,
    context: str,
) -> list[CommandInvocation]:
    """Walk inner content of command_substitution or process_substitution."""
    results: list[CommandInvocation] = []
    for child in node.children:
        if child.type in ("$(", ")", "<(", ">(", "`"):
            continue
        results.extend(_walk_node(child, context=context, operator_before=None))
    return results


def _extract_command(
    node: tree_sitter.Node,
    *,
    context: str,
    operator_before: str | None,
    pipeline_position: int,
    pipeline_length: int,
) -> CommandInvocation | None:
    """Extract a CommandInvocation from a 'command' node."""
    argv: list[str] = []
    has_command_name = False

    for child in node.children:
        if child.type == "variable_assignment":
            # Strip variable assignments before the command name
            if not has_command_name:
                continue
            # After command name, treat as argument
            argv.append(_node_text(child))
        elif child.type == "command_name":
            has_command_name = True
            argv.append(_node_text(child))
        elif child.type in ("file_redirect", "heredoc_redirect", "herestring_redirect"):
            # Handled separately
            continue
        elif child.type == "comment":
            continue
        else:
            # Arguments: word, string, raw_string, concatenation, etc.
            argv.append(_node_text(child))

    if not argv:
        return None

    redirects = _extract_redirects_from_node(node)

    return CommandInvocation(
        argv=argv,
        redirects=redirects,
        position_in_pipeline=pipeline_position,
        pipeline_length=pipeline_length,
        context=context,
        operator_before=operator_before,
        is_background=False,
    )


def _extract_test_command(
    node: tree_sitter.Node,
    *,
    context: str,
    operator_before: str | None,
    pipeline_position: int,
    pipeline_length: int,
) -> CommandInvocation | None:
    """Extract a CommandInvocation from a 'test_command' node ([ ... ] or [[ ... ]])."""
    # The first child is '[' or '[[', use it as the command name
    argv: list[str] = []
    for child in node.children:
        if child.type in ("[", "[["):
            argv.append(child.text.decode())
        elif child.type in ("]", "]]"):
            # Closing bracket is not part of argv
            continue
        elif child.is_named:
            argv.append(_node_text(child))

    if not argv:
        return None

    return CommandInvocation(
        argv=argv,
        redirects=[],
        position_in_pipeline=pipeline_position,
        pipeline_length=pipeline_length,
        context=context,
        operator_before=operator_before,
        is_background=False,
    )


def _extract_nested_from_command_args(node: tree_sitter.Node) -> list[CommandInvocation]:
    """Extract commands from nested command_substitution/process_substitution within command arguments."""
    results: list[CommandInvocation] = []
    for child in node.children:
        if child.type == "command_name":
            # Recurse into command_name children for command substitutions
            for sub in child.children:
                results.extend(_find_nested_substitutions(sub))
        elif child.type in ("file_redirect", "heredoc_redirect", "herestring_redirect", "variable_assignment"):
            continue
        else:
            results.extend(_find_nested_substitutions(child))
    return results


def _find_nested_substitutions(node: tree_sitter.Node) -> list[CommandInvocation]:
    """Recursively find command_substitution and process_substitution nodes in arguments."""
    results: list[CommandInvocation] = []

    if node.type == "command_substitution":
        results.extend(_walk_compound_inner(node, context="command_substitution"))
    elif node.type == "process_substitution":
        results.extend(_walk_compound_inner(node, context="process_substitution"))
    else:
        for child in node.children:
            results.extend(_find_nested_substitutions(child))

    return results


def _extract_redirects_from_node(node: tree_sitter.Node) -> list[Redirect]:
    """Extract Redirect objects from a node's redirect children."""
    redirects: list[Redirect] = []
    for child in node.children:
        if child.type == "file_redirect":
            redirect = _parse_file_redirect(child)
            if redirect is not None:
                redirects.append(redirect)
        elif child.type == "heredoc_redirect":
            redirect = _parse_heredoc_redirect(child)
            if redirect is not None:
                redirects.append(redirect)
        elif child.type == "herestring_redirect":
            redirect = _parse_herestring_redirect(child)
            if redirect is not None:
                redirects.append(redirect)
    return redirects


def _parse_file_redirect(node: tree_sitter.Node) -> Redirect | None:
    """Parse a file_redirect node into a Redirect."""
    # file_redirect children: optional fd, operator, target
    operator_parts: list[str] = []
    target = ""

    for child in node.children:
        if child.type == "file_descriptor" or child.type in (">", ">>", "<", ">&", "&>", "&>>", "<&", "<<", "<<<"):
            operator_parts.append(child.text.decode())
        elif child.is_named:
            target = _node_text(child)
        else:
            # Unnamed nodes that are operators
            text = child.text.decode()
            if text in (">", ">>", "<", ">&", "&>", "&>>", "<&", "<<", "<<<"):
                operator_parts.append(text)
            elif not target:
                target = text

    operator = "".join(operator_parts)
    if not operator:
        # Fallback: extract operator from the full text
        full_text = node.text.decode()
        if ">" in full_text or "<" in full_text:
            operator = full_text.split()[0] if full_text.split() else full_text

    affects = _redirect_affects_classification(operator, target)

    return Redirect(operator=operator, target=target, affects_classification=affects)


def _parse_heredoc_redirect(node: tree_sitter.Node) -> Redirect | None:
    """Parse a heredoc_redirect node into a Redirect."""
    # Extract the heredoc delimiter
    operator = "<<"
    target = ""

    for child in node.children:
        if child.type in ("<<", "<<-"):
            operator = child.text.decode()
        elif child.type == "heredoc_start":
            target = child.text.decode()

    return Redirect(operator=operator, target=target, affects_classification=False)


def _parse_herestring_redirect(node: tree_sitter.Node) -> Redirect | None:
    """Parse a herestring_redirect node (<<<) into a Redirect."""
    target = ""
    for child in node.children:
        if child.type == "<<<":
            continue
        elif child.is_named:
            target = _node_text(child)
        else:
            text = child.text.decode()
            if text != "<<<" and not target:
                target = text

    return Redirect(operator="<<<", target=target, affects_classification=False)


def _redirect_affects_classification(operator: str, target: str) -> bool:
    """Determine if a redirect affects classification (i.e., writes to a file)."""
    if target == "/dev/null":
        return False
    # fd-to-fd redirects like 2>&1, 1>&2 do not affect classification
    if ">&" in operator and target.isdigit():
        return False
    # Output redirects affect classification
    if operator in (">", ">>", "&>", "&>>") or (operator.endswith(">") and "<" not in operator):
        return True
    # Numbered output redirects like 2>
    return len(operator) >= 2 and operator[0].isdigit() and ">" in operator


def _node_text(node: tree_sitter.Node) -> str:
    """Extract the text content of a node, stripping outer quotes from string nodes.

    - `string` nodes ("...") have their outer double quotes stripped.
    - `raw_string` nodes ('...') have their outer single quotes stripped.
    - `$'...'` (ANSI-C quoting) is also stripped.
    - `concatenation` nodes join their children (each child processed).
    - Regular `word` nodes are returned as-is.
    """
    if node.type == "string":
        # Double-quoted string: "content"
        text = node.text.decode()
        if len(text) >= 2 and text[0] == '"' and text[-1] == '"':
            return text[1:-1]
        return text
    elif node.type == "raw_string":
        # Single-quoted string: 'content' or $'content'
        text = node.text.decode()
        if len(text) >= 2 and text[0] == "'" and text[-1] == "'":
            return text[1:-1]
        if len(text) >= 3 and text[:2] == "$'" and text[-1] == "'":
            return text[2:-1]
        return text
    elif node.type == "ansi_c_string":
        # ANSI-C quoted string: $'content'
        text = node.text.decode()
        if len(text) >= 3 and text[:2] == "$'" and text[-1] == "'":
            return text[2:-1]
        return text
    elif node.type == "concatenation":
        # Join children, each processed individually
        return "".join(_node_text(child) for child in node.children)
    else:
        return node.text.decode()


def _mark_last_background(results: list[CommandInvocation]) -> None:
    """Mark the last command in the results list as background."""
    if results:
        results[-1].is_background = True
