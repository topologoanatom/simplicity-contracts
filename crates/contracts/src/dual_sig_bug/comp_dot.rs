use std::collections::HashMap;

pub fn convert_to_dot(compiled_str: &str) -> String {
    let mut res = String::new();

    res.push_str("digraph DAG {{");
    res.push_str("  rankdir=LR;");
    res.push_str("  node [shape=box, fontname=\"Courier\"];");

    let mut references: HashMap<usize, Vec<usize>> = HashMap::new();

    for line in compiled_str.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        if let Some((idx_str, rest)) = line.split_once(':') {
            let idx: usize = idx_str.trim().parse().unwrap();
            let op = rest.trim();

            let color = if op.starts_with("jet(") {
                "lightblue"
            } else if op.starts_with("assert") {
                "orange"
            } else if op.starts_with("drop") {
                "yellow"
            } else if op.starts_with("comp") || op.starts_with("pair") {
                "lightgreen"
            } else {
                "white"
            };

            res.push_str(&format!(
                "  n{} [label=\"{}: {}\", style=filled, fillcolor={}];",
                idx,
                idx,
                op.replace("\"", "\\\""),
                color
            ));

            extract_refs(op, idx, &mut references);
        }
    }

    for (from, tos) in references.iter() {
        for to in tos {
            res.push_str(&format!("  n{} -> n{};", from, to));
        }
    }

    res.push_str("}}");

    res
}

fn extract_refs(op: &str, from: usize, refs: &mut HashMap<usize, Vec<usize>>) {
    let inner = op.split('(').nth(1).and_then(|s| s.split(')').next());
    if let Some(args) = inner {
        for arg in args.split(',') {
            if let Ok(to) = arg.trim().parse::<usize>() {
                refs.entry(from).or_insert_with(Vec::new).push(to);
            }
        }
    }
}
