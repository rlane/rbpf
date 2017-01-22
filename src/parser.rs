use combine::char::{char, letter, spaces, digit};
use combine::{many1, parser, Parser};
use combine::primitives::{Stream, ParseResult};
use combine::ParseError;

#[derive(Debug, PartialEq)]
pub enum Instruction {
    Addi(String, i32, i32),
}

fn instruction<I>(input: I) -> ParseResult<Instruction, I>
    where I: Stream<Item=char>
{
    let word = many1(letter());
    let mut reg = char('r').with(many1(digit())).map(|t: String| t.parse::<i32>().unwrap());
    let mut integer = many1(digit()).map(|t: String| t.parse::<i32>().unwrap());
    let mut line = (word.skip(spaces()),
                    reg.skip(spaces()),
                    char(',').skip(spaces()),
                    integer.skip(spaces()))
        .map(|t| Instruction::Addi(t.0, t.1, t.3));
    line.parse_stream(input)
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
fn test_addi() {
  assert_eq!(
    parse("addi r1, 2"),
    Ok(vec!(Instruction::Addi("addi".to_string(), 1, 2))));
}
