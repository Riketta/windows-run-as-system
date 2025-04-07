use std::{env, process::ExitCode};

use windows::{
    Win32::{
        Foundation::*,
        Security::*,
        System::{
            Diagnostics::ToolHelp::*, SystemServices::*, Threading::*, WindowsProgramming::*,
        },
    },
    core::*,
};

fn FindProcess(name: PCWSTR) -> anyhow::Result<u32> {
    unsafe {
        let snapshot_handle = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)?;
        let mut process_entry = PROCESSENTRY32W::default();
        process_entry.dwSize = size_of::<PROCESSENTRY32W>() as u32;

        Process32FirstW(snapshot_handle, &mut process_entry)?;

        let mut pid = 0;
        while Process32NextW(snapshot_handle, &mut process_entry).is_ok() {
            let other_name = process_entry.szExeFile.as_ptr();
            let equal = uaw_wcsicmp(name.as_ptr(), other_name) == 0;
            if equal {
                pid = process_entry.th32ProcessID;
                break;
            }
        }
        CloseHandle(snapshot_handle)?;

        return Ok(pid);
    }
}

fn parse_args(args: Vec<String>) -> (String, String) {
    let own_args: Vec<String> = args
        .clone()
        .into_iter()
        .take_while(|arg| arg != "--")
        .collect();
    let target_args: Vec<String> = args.into_iter().skip(own_args.len() + 1).collect();

    let executable_path = own_args
        .into_iter()
        .skip_while(|arg| arg != &"--path")
        .skip(1)
        .next()
        .expect("command line arguments should contain --path <path>");

    // TODO: validate.
    let mut target_args: String = target_args
        .iter()
        .map(|arg| arg.replace(r#"""#, r#"\""#))
        .map(|arg| {
            if arg.contains(" ") {
                format!(r#""{arg}""#)
            } else {
                arg
            }
        })
        .collect();

    if !executable_path.is_empty() {
        target_args = format!("{executable_path} {target_args}");
    }

    (executable_path, target_args)
}

fn main() -> ExitCode {
    let (executable_path, target_args) = parse_args(env::args().map(|arg| arg).collect());

    let Ok(pid) = FindProcess(w!("lsass.exe")) else {
        return ExitCode::from(1);
    };

    unsafe {
        let Ok(process_handle) = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) else {
            return ExitCode::from(2);
        };

        let mut token_handle = HANDLE::default();
        if OpenProcessToken(process_handle, TOKEN_DUPLICATE, &mut token_handle).is_err() {
            return ExitCode::from(3);
        };

        let mut duplicate_token_handle = HANDLE::default();
        if DuplicateTokenEx(
            token_handle,
            windows::Win32::Security::TOKEN_ACCESS_MASK(MAXIMUM_ALLOWED),
            None,
            SecurityIdentification,
            TokenPrimary,
            &mut duplicate_token_handle,
        )
        .is_err()
        {
            return ExitCode::from(4);
        }

        let executable_path = HSTRING::from(&executable_path);
        let mut target_args = target_args.encode_utf16().collect::<Vec<u16>>();
        target_args.push(0);

        let executable_path = PCWSTR::from_raw(executable_path.as_ptr());
        let target_args = PWSTR::from_raw(target_args.as_mut_ptr());

        let mut process_information = PROCESS_INFORMATION::default();
        let mut startup_info = STARTUPINFOW::default();

        if let Err(e) = CreateProcessWithTokenW(
            duplicate_token_handle,
            windows::Win32::System::Threading::CREATE_PROCESS_LOGON_FLAGS(0),
            executable_path,
            Some(target_args),
            windows::Win32::System::Threading::PROCESS_CREATION_FLAGS(0),
            None,
            None,
            &mut startup_info,
            &mut process_information,
        ) {
            eprintln!("{e}");
            let _error = GetLastError();
            return ExitCode::from(5);
        };
    }

    ExitCode::from(0)
}

#[cfg(test)]
mod tests {
    type Error = Box<dyn std::error::Error>;
    type Result<T> = core::result::Result<T, Error>; // For tests.

    use super::*;

    #[test]
    fn test_cli_parsing() -> Result<()> {
        // TODO: adopt <https://github.com/ChrisDenton/winarg>.

        let args = vec![
            "C:\\ThisExecutable.exe",
            "--path",
            r#"C:\Program Files\Notepad++\notepad++.exe"#,
            "--",
            r#"D:\DummySampleSimple DB.txt"#,
        ]
        .into_iter()
        .map(&str::to_string)
        .collect();

        let (executable_path, target_args) = parse_args(args);

        assert_eq!(
            executable_path,
            r#"C:\Program Files\Notepad++\notepad++.exe"#
        );
        assert_eq!(
            target_args,
            r#"C:\Program Files\Notepad++\notepad++.exe "D:\DummySampleSimple DB.txt""#
        );

        Ok(())
    }
}
