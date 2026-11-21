#[derive(Debug, PartialEq, Clone)]
enum Toking {
    Dn,
    memmory,
    Mut,
    su,
    so,
    hardware,
    If,
    have,
    Else,
    what,
    say,
    sudo,
    import,
    gpu,
    cpu,
    
   

} 
pub struct Token {
    pub token: Toking,
    pub value: String,
}