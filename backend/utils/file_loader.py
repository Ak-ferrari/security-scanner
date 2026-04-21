def read_file(path):
    try:
        with open(path, "r") as file:
            return file.read()
    except Exception:
        return None