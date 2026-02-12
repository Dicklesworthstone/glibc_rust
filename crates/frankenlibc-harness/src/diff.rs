//! Diff rendering for fixture comparison.

/// Render a text diff between expected and actual output.
#[must_use]
pub fn render_diff(expected: &str, actual: &str) -> String {
    #[cfg(feature = "frankentui-ui")]
    {
        return ftui_harness::diff_text(expected, actual);
    }

    #[cfg(not(feature = "frankentui-ui"))]
    {
        if expected == actual {
            return String::from("[identical]");
        }

        let mut out = String::new();
        out.push_str("--- expected\n");
        out.push_str("+++ actual\n");
        for (i, (e, a)) in expected.lines().zip(actual.lines()).enumerate() {
            if e != a {
                out.push_str(&format!("@@ line {} @@\n", i + 1));
                out.push_str(&format!("-{e}\n"));
                out.push_str(&format!("+{a}\n"));
            }
        }
        out
    }
}
