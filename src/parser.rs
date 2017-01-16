use combine;
use combine::char::{char, letter, spaces, digit};
use combine::{between, many1, parser, sep_by, Parser};
use combine::primitives::{State, Stream, ParseResult};

#[derive(Debug, PartialEq)]
enum Instruction {
    Addi(String, i32, i32),
}

fn instruction<I>(input: I) -> ParseResult<Instruction, I>
    where I: Stream<Item=char>
{
    let mut word = many1(letter());
    let mut reg = char('r').with(many1(digit())).map(|t: String| t.parse::<i32>().unwrap());
    let mut integer = many1(digit()).map(|t: String| t.parse::<i32>().unwrap());
    let mut line = (word.skip(spaces()),
                    reg.skip(spaces()),
                    char(',').skip(spaces()),
                    integer.skip(spaces()))
        .map(|t| Instruction::Addi(t.0, t.1, t.3));
    line.parse_stream(input)
}

#[test]
fn test_parse() {
  let result = combine::parser(instruction).parse("addi r1, 2");
  let expected = 0;
  assert_eq!(result, Ok((Instruction::Addi("addi".to_string(), 1, 2), "")));
}
