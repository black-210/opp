mod compiler;
use compiler::lexer::Lexer;
fn main() {
    let input = "fn main() { let x = 5; }";
    let mut lexer = Lexer::new(input);
    let tokens = lexer.lex();
    match tokens {
        Ok(tokens) => {
            for token in tokens {
                println!("{:?}", token);
            }
        }
        Err(e) => {
            eprintln!("Error: {}", e);
        }
    }
   
    }

fn  peek_next_token(lexer: &mut Lexer) -> Option<Toking> {
    match lexer.peek() {
        Some(token) => Some(Toking::new(token.token.clone(), token.value.clone())),
        None => None,
    }
}
