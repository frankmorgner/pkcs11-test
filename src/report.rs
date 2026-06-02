use colored::*;
use std::cell::RefCell;

#[derive(Debug, Clone)]
pub struct Mismatch {
    pub field: String,
    pub error: String,
}

#[derive(Debug, Clone)]
pub enum StepResult {
    Pass,
    Mismatch(Vec<Mismatch>),
    Failed(String),
}

#[derive(Debug, Clone)]
pub struct TestStep {
    pub context_id: usize,
    pub function_name: Option<String>,
    pub result: StepResult,
}

thread_local! {
    static TEST_REPORT: RefCell<Vec<TestStep>> = const { RefCell::new(Vec::new()) };
    static CURRENT_CONTEXT: RefCell<Option<(usize, String)>> = const { RefCell::new(None) };
    static CONTEXT_COUNTER: RefCell<usize> = const { RefCell::new(0) };
}

pub fn set_context(name: &str) {
    let id = CONTEXT_COUNTER.with(|c| {
        let mut val = c.borrow_mut();
        *val += 1;
        *val
    });

    CURRENT_CONTEXT.with(|c| *c.borrow_mut() = Some((id, name.to_string())));
}

pub fn record_result(result: StepResult) {
    let current = CURRENT_CONTEXT.with(|c| c.borrow().clone());

    let (ctx_id, name) = match current {
        Some((id, n)) => (id, Some(n)),
        None => (0, None),
    };

    TEST_REPORT.with(|r| {
        r.borrow_mut().push(TestStep {
            context_id: ctx_id,
            function_name: name,
            result,
        });
    });
}

pub fn print_report(test_file: &str) {
    println!("\n{} {}", "Starting test".bold(), test_file.blue());
    println!("{}", "------------------------------------------------------------".dimmed());

    let steps = TEST_REPORT.with(|r| r.borrow().clone());
    
    let failed_context_ids: std::collections::HashSet<usize> = steps
        .iter()
        .filter(|step| match step.result {
            StepResult::Mismatch(_) | StepResult::Failed(_) => true,
            StepResult::Pass => false,
        })
        .map(|step| step.context_id)
        .collect();

    let mut stats = (0, 0, 0, 0); // total, passed, mismatches, failed
    let mut last_warn_context_id: Option<usize> = None;

    for step in steps {
        let name = step.function_name.unwrap_or_else(|| "[Unknown Context]".to_string());

        match step.result {
            StepResult::Pass => {
                // if a mismatch exists, don't report as passed
                if failed_context_ids.contains(&step.context_id) {
                    continue;
                }
                stats.0 += 1;
                stats.1 += 1;
                println!("{} {}", "[PASS]".green(), name.bold());
            }
            StepResult::Mismatch(list) => {
                stats.0 += 1;
                stats.1 += 1; // counts as executed
                stats.2 += list.len();

                let is_new_context = (last_warn_context_id != Some(step.context_id)) || step.context_id == 0;

                if is_new_context {
                    println!("{} {}", "[WARN]".yellow(), name.bold());
                    last_warn_context_id = Some(step.context_id);
                }

                for m in list {
                    println!("     ↳ {}", m.field);
                    println!("       {}", m.error.italic());
                }
            }
            StepResult::Failed(err) => {
                stats.0 += 1;
                stats.3 += 1;
                println!("{} {}", "[FAIL]".red(), name.bold());
                println!("     ↳ {}", err.italic());
            }
        }
    }

    println!("{}", "------------------------------------------------------------".dimmed());
    println!("TEST SUMMARY: Total {}, Passed {}, Mismatches {}, Failed {}",
        stats.0.to_string().blue(),
        stats.1.to_string().green(),
        if stats.2 > 0 { stats.2.to_string().yellow() } else { "0".green() },
        if stats.3 > 0 { stats.3.to_string().red() } else { "0".green() }
    );

    CONTEXT_COUNTER.with(|c| *c.borrow_mut() = 0);
    CURRENT_CONTEXT.with(|c| *c.borrow_mut() = None);
    TEST_REPORT.with(|r| r.borrow_mut().clear());
}
