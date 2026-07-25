pub(crate) fn model_arg(args: &[String]) -> Option<String> {
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        if let Some(model) = arg.strip_prefix("--model=")
            && !model.is_empty()
        {
            return Some(model.to_string());
        }
        if matches!(arg.as_str(), "--model" | "-m")
            && let Some(model) = iter.next()
            && !model.trim().is_empty()
        {
            return Some(model.to_string());
        }
    }
    None
}

pub(crate) fn args_without_model(args: &[String]) -> Vec<String> {
    let mut out = Vec::with_capacity(args.len());
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        if matches!(arg.as_str(), "--model" | "-m") {
            let _ = iter.next();
            continue;
        }
        if arg.starts_with("--model=") {
            continue;
        }
        out.push(arg.clone());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_long_short_and_equals_model_arguments() {
        assert_eq!(
            model_arg(&["--model".into(), "llama3.2".into()]),
            Some("llama3.2".into())
        );
        assert_eq!(
            model_arg(&["--model=qwen3.5".into()]),
            Some("qwen3.5".into())
        );
        assert_eq!(
            model_arg(&["-m".into(), "gemma4".into()]),
            Some("gemma4".into())
        );
        assert_eq!(model_arg(&["--model".into()]), None);
    }

    #[test]
    fn removes_model_arguments_without_disturbing_other_arguments() {
        assert_eq!(
            args_without_model(&[
                "--debug".into(),
                "--model".into(),
                "qwen3.7-plus".into(),
                "--verbose".into(),
            ]),
            vec!["--debug", "--verbose"]
        );
        assert_eq!(
            args_without_model(&["--model=qwen3.7-plus".into(), "hello".into()]),
            vec!["hello"]
        );
    }
}
