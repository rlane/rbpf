use combine::char::{char, spaces, digit, alpha_num};
use combine::{many1, parser, Parser, sep_by};
use combine::primitives::{Stream, ParseResult};
use combine::ParseError;

#[derive(Debug, PartialEq)]
pub enum Operand {
    Register(i32),
    Offset(i32),
    Immediate(i32),
    Memory(i32, i32),
}

#[derive(Debug, PartialEq)]
pub struct Instruction {
    pub name: String,
    pub operands: Vec<Operand>,
}

fn ident<I>(input: I) -> ParseResult<String, I>
    where I: Stream<Item = char>
{
    many1(alpha_num()).parse_stream(input)
}

// TODO hexadecimal, +/-.
fn integer<I>(input: I) -> ParseResult<i32, I>
    where I: Stream<Item = char>
{
    many1(digit()).map(|t: String| t.parse::<i32>().unwrap()).parse_stream(input)
}

fn operand<I>(input: I) -> ParseResult<Operand, I>
    where I: Stream<Item = char>
{
    let register = char('r').with(parser(integer)).map(|x: i32| Operand::Register(x));
    let immediate = parser(integer).map(|x: i32| Operand::Immediate(x));
    // TODO memory
    register.or(immediate).parse_stream(input)
}

fn instruction<I>(input: I) -> ParseResult<Instruction, I>
    where I: Stream<Item = char>
{
    (parser(ident).skip(spaces()), sep_by(parser(operand), char(',').skip(spaces())))
        .map(|t| {
            Instruction {
                name: t.0,
                operands: t.1,
            }
        })
        .parse_stream(input)
}

pub fn parse<I>(input: I) -> Result<Vec<Instruction>, ParseError<I>>
    where I: Stream<Item = char>
{
    match parser(instruction).parse(input) {
        Ok((inst, _)) => Ok(vec![inst]),
        Err(err) => Err(err),
    }
}

#[test]
fn test_ident() {
    assert_eq!(parser(ident).parse("nop"), Ok(("nop".to_string(), "")));

    assert_eq!(parser(ident).parse("add32"), Ok(("add32".to_string(), "")));

    assert_eq!(parser(ident).parse("add32*"),
               Ok(("add32".to_string(), "*")));
}

#[test]
fn test_integer() {
    assert_eq!(parser(integer).parse("0"), Ok((0, "")));

    assert_eq!(parser(integer).parse("42"), Ok((42, "")));
}

#[test]
fn test_operand() {
    assert_eq!(parser(operand).parse("r0"), Ok((Operand::Register(0), "")));

    assert_eq!(parser(operand).parse("r15"),
               Ok((Operand::Register(15), "")));
}

#[test]
fn test_instruction() {
    assert_eq!(parser(instruction).parse("exit"),
               Ok((Instruction {
                       name: "exit".to_string(),
                       operands: vec![],
                   },
                   "")));

    assert_eq!(parser(instruction).parse("call 2"),
               Ok((Instruction {
                       name: "call".to_string(),
                       operands: vec![Operand::Immediate(2)],
                   },
                   "")));

    assert_eq!(parser(instruction).parse("addi r1, 2"),
               Ok((Instruction {
                       name: "addi".to_string(),
                       operands: vec![Operand::Register(1), Operand::Immediate(2)],
                   },
                   "")));
}

#[test]
fn test_parse() {
    assert_eq!(parse("exit"),
               Ok(vec![Instruction {
                           name: "exit".to_string(),
                           operands: vec![],
                       }]))
}
