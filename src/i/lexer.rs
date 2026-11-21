use super::lexer::Lexer;
pub struct Toking {
    pub token: String,
    pub value: String,
}
impl<i> Toking {
    pub fn new(token: String, value: String) -> Self {
        Toking { token, value }
    }
}
fn peek_next_token(lexer: &mut Lexer) -> Option<Toking> {
    let current_position = lexer.position;
    let next_token = lexer.next_token();
    lexer.position = current_position;
    next_token;
    some(next_token)
}
fn skip_whitespace(lexer: &mut Lexer) {
    while let Some(token) = peek_next_token(lexer) {
        if token.token == " " || token.token == "\n" || token.token == "\t" {
            lexer.next_token();
        } else {
            break;
        }
    }
}
fn identify_token(token: &str) -> Option<Toking> {
    match token {
        "fn" => Some(Toking::new("fn".to_string(), token.to_string())),
        "memmory" => Some(Toking::new("memmory".to_string(), token.to_string())),
        "mut" => Some(Toking::new("mut".to_string(), token.to_string())),
        "su" => Some(Toking::new("su".to_string(), token.to_string())),
        "for" => Some(Toking::new("for".to_string(), token.to_string())),
        "hardware" => Some(Toking::new("hardware".to_string(), token.to_string())),
        "if" => Some(Toking::new("if".to_string(), token.to_string())),
        "have" => Some(Toking::new("have".to_string(), token.to_string())),
        "else" => Some(Toking::new("else".to_string(), token.to_string())),
        "what" => Some(Toking::new("what".to_string(), token.to_string())),
        "say" => Some(Toking::new("say".to_string(), token.to_string())),
        "sudo" => Some(Toking::new("sudo".to_string(), token.to_string())),
        "import" => Some(Toking::new("import".to_string(), token.to_string())),
        "gpu" => Some(Toking::new("gpu".to_string(), token.to_string())),
        "cpu" => Some(Toking::new("cpu".to_string(), token.to_string())),
        _ => None,
    }
}
fn lex(lexer: &mut Lexer) -> Vec<Toking> {
    let mut tokens = Vec::new();
    while let Some(token) = lexer.next_token() {
        if let Some(toking) = identify_token(&token.token) {
            tokens.push(toking);
        } else {
            tokens.push(Toking::new(token.token, token.value));
        }
    }
    tokens
}
fn number(lexer: &mut Lexer) -> Option<Toking> {
    let mut number = String::new();
    while let Some(token) = peek_next_token(lexer) {
        if token.token.chars().all(|c| c.is_digit(10)) {
            number.push_str(&token.token);
            lexer.next_token();
        } else {
            break;
        }
    }
    if !number.is_empty() {
        Some(Toking::new("number".to_string(), number))
    } else {
        None
    }
}
pub fn tokenize(input: &str) -> Vec<Toking> {
    let mut lexer = Lexer::new(input);
    let mut tokens = Vec::new();
    while let Some(token) = lexer.next_token() {
        if let Some(toking) = identify_token(&token.token) {
            tokens.push(toking);
        } else if let Some(number_token) = number(&mut lexer) {
            tokens.push(number_token);
        } else {
            tokens.push(Toking::new(token.token, token.value));
        }
        let kind = peek_next_token(&mut lexer);
        if let Some(kind) = kind {  
            Toking::new(kind.token, kind.value);
    }
}
}
fn hardware(lexer: &mut Lexer) -> Option<Toking> {
    let mut hardware = String::new();
    while let Some(token) = peek_next_token(lexer) {
        if token.token.chars().all(|c| c.is_alphanumeric()) {
            hardware.push_str(&token.token);
            lexer.next_token();
        } else {
            break;
        }
    }
    if !hardware.is_empty() {
        Some(Toking::new("hardware".to_string(), hardware))
    } else {
        None
    }
}
fn import(lexer: &mut Lexer) -> Option<Toking> {
    let mut import = String::new();
    while let Some(token) = peek_next_token(lexer) {
        if token.token.chars().all(|c| c.is_alphanumeric()) {
            import.push_str(&token.token);
            lexer.next_token();
        } else {
            break;
        }
    }
    if !import.is_empty() {
        Some(Toking::new("import".to_string(), import))
    } else {
        None
    }
}
fn say(lexer: &mut Lexer) -> Option<Toking> {
    let mut say = String::new();
    while let Some(token) = peek_next_token(lexer) {
        if token.token.chars().all(|c| c.is_alphanumeric()) {
            say.push_str(&token.token);
            lexer.next_token();
        } else {
            break;
        }
    }
    if !say.is_empty() {
        Some(Toking::new("say".to_string(), say))
    } else {
        None
    }
}
fn sudo(lexer: &mut Lexer) -> Option<Toking> {
    let mut sudo = String::new();
    while let Some(token) = peek_next_token(lexer) {
        if token.token.chars().all(|c| c.is_alphanumeric()) {
            sudo.push_str(&token.token);
            lexer.next_token();
        } else {
            break;
        }
    }
    if !sudo.is_empty() {
        Some(Toking::new("sudo".to_string(), sudo))
    } else {
        None
    }
}
fn cpu(lexer: &mut Lexer) -> Option<Toking> {
    let mut cpu = String::new();
    while let Some(token) = peek_next_token(lexer) {
        if token.token.chars().all(|c| c.is_alphanumeric()) {
            cpu.push_str(&token.token);
            lexer.next_token();
        } else {
            break;
        }
    }
    if !cpu.is_empty() {
        Some(Toking::new("cpu".to_string(), cpu))
    } else {
        None
    }
}
fn gpu(lexer: &mut Lexer) -> Option<Toking> {
    let mut gpu = String::new();
    while let Some(token) = peek_next_token(lexer) {
        if token.token.chars().all(|c| c.is_alphanumeric()) {
            gpu.push_str(&token.token);
            lexer.next_token();
        } else {
            break;
        }
    }
    if !gpu.is_empty() {
        Some(Toking::new("gpu".to_string(), gpu))
    } else {
        None
        
    }
}

fn memmory(lexer: &mut Lexer) -> Option<Toking> {
    let mut memmory = String::new();
    while let Some(token) = peek_next_token(lexer) {
        if token.token.chars().all(|c| c.is_alphanumeric()) {
            memmory.push_str(&token.token);
            lexer.next_token();
        } else {
            break;
        }
    }
    if !memmory.is_empty() {
        Some(Toking::new("memmory".to_string(), memmory))
    } else {
        None
    }
}