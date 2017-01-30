use combine::char::{char, spaces, digit, alpha_num, hex_digit, string};
use combine::{many1, parser, Parser, sep_by, optional, one_of, try};
use combine::primitives::{Stream, ParseResult};
use combine::ParseError;

#[derive(Debug, PartialEq)]
pub enum Operand {
    Register(i64),
    Integer(i64),
    Memory(i64, i64),
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

fn integer<I>(input: I) -> ParseResult<i64, I>
    where I: Stream<Item = char>
{
    let sign = optional(one_of("-+".chars())).map(|x| match x {
        Some('-') => -1,
        _ => 1,
    });
    let hex =
        string("0x").with(many1(hex_digit())).map(|x: String| i64::from_str_radix(&x, 16).unwrap());
    let dec = many1(digit()).map(|x: String| i64::from_str_radix(&x, 10).unwrap());
    (sign, try(hex).or(dec)).map(|(s, x)| s * x).parse_stream(input)
}

fn operand<I>(input: I) -> ParseResult<Operand, I>
    where I: Stream<Item = char>
{
    let register = char('r').with(parser(integer)).map(|x: i64| Operand::Register(x));
    let immediate = parser(integer).map(|x: i64| Operand::Integer(x));
    let memory = (char('['),
                  char('r'),
                  parser(integer),
                  optional(char('+').with(parser(integer))),
                  char(']'))
        .map(|t: (_, _, i64, Option<i64>, _)| Operand::Memory(t.2, t.3.unwrap_or(0)));
    register.or(immediate).or(memory).parse_stream(input)
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

    assert_eq!(parser(integer).parse("+42"), Ok((42, "")));

    assert_eq!(parser(integer).parse("-42"), Ok((-42, "")));

    assert_eq!(parser(integer).parse("0x0"), Ok((0, "")));

    assert_eq!(parser(integer).parse("0x123456789abcdef0"),
               Ok((0x123456789abcdef0, "")));
}

#[test]
fn test_operand() {
    assert_eq!(parser(operand).parse("r0"), Ok((Operand::Register(0), "")));

    assert_eq!(parser(operand).parse("r15"),
               Ok((Operand::Register(15), "")));

    assert_eq!(parser(operand).parse("0"), Ok((Operand::Integer(0), "")));

    assert_eq!(parser(operand).parse("42"), Ok((Operand::Integer(42), "")));

    assert_eq!(parser(operand).parse("[r1]"),
               Ok((Operand::Memory(1, 0), "")));

    assert_eq!(parser(operand).parse("[r3+5]"),
               Ok((Operand::Memory(3, 5), "")));
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
                       operands: vec![Operand::Integer(2)],
                   },
                   "")));

    assert_eq!(parser(instruction).parse("addi r1, 2"),
               Ok((Instruction {
                       name: "addi".to_string(),
                       operands: vec![Operand::Register(1), Operand::Integer(2)],
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
