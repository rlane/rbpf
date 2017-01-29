use combine::char::{char, spaces, digit, alpha_num};
use combine::{many1, parser, Parser};
use combine::primitives::{Stream, ParseResult};
use combine::ParseError;

#[derive(Debug, PartialEq)]
pub enum Instruction {
    Addi(String, i32, i32),
}

fn ident<I>(input: I) -> ParseResult<String, I>
    where I: Stream<Item=char>
{
    many1(alpha_num()).parse_stream(input)
}

// TODO hexadecimal.
fn integer<I>(input: I) -> ParseResult<i32, I>
    where I: Stream<Item=char>
{
    many1(digit()).map(|t: String| t.parse::<i32>().unwrap()).parse_stream(input)
}

fn register<I>(input: I) -> ParseResult<i32, I>
    where I: Stream<Item=char>
{
    char('r').with(parser(integer)).parse_stream(input)
}

fn instruction<I>(input: I) -> ParseResult<Instruction, I>
    where I: Stream<Item=char>
{
    (parser(ident).skip(spaces()),
        parser(register).skip(spaces()),
        char(',').skip(spaces()),
        parser(integer).skip(spaces()))
            .map(|t| Instruction::Addi(t.0, t.1, t.3)).parse_stream(input)
}

pub fn parse<I>(input: I) -> Result<Vec<Instruction>, ParseError<I>>
    where I: Stream<Item=char>
{
   match parser(instruction).parse(input) {
     Ok((inst, _)) => Ok(vec!(inst)),
     Err(err) => Err(err)
   }
}

#[test]
fn test_ident() {
  assert_eq!(
    parser(ident).parse("nop"),
    Ok(("nop".to_string(), "")));

  assert_eq!(
    parser(ident).parse("add32"),
    Ok(("add32".to_string(), "")));

  assert_eq!(
    parser(ident).parse("add32*"),
    Ok(("add32".to_string(), "*")));
}

#[test]
fn test_integer() {
  assert_eq!(
    parser(integer).parse("0"),
    Ok((0, "")));

  assert_eq!(
    parser(integer).parse("42"),
    Ok((42, "")));
}

#[test]
fn test_register() {
  assert_eq!(
    parser(register).parse("r0"),
    Ok((0, "")));

  assert_eq!(
    parser(register).parse("r15"),
    Ok((15, "")));
}

#[test]
fn test_addi() {
  assert_eq!(
    parse("addi r1, 2"),
    Ok(vec!(Instruction::Addi("addi".to_string(), 1, 2))));
}
