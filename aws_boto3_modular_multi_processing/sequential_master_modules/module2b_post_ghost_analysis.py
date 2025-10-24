def main():
    log_path = "/aws_EC2/logs/gitlab_full_run.log"
    match_phrase = "install_success"

    print(f"[TRACE][module2b] Starting ghost log scan for phrase: '{match_phrase}'")

    try:
        with open(log_path, "r") as f:
            match_count = 0
            for line in f:
                if match_phrase in line:
                    print(f"[MATCH] {line.strip()}")
                    match_count += 1
        print(f"[TRACE][module2b] Total matches found: {match_count}")
    except FileNotFoundError:
        print(f"[ERROR][module2b] Log file not found: {log_path}")








# for master file indirection:
if __name__ == "__main__":
    main()

