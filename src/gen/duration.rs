use std::time::Duration;

use nom::IResult;

use crate::prelude::*;

const SECS_PER_YEAR: u64 = 365 * SECS_PER_DAY;
const SECS_PER_MONTH: u64 = 30 * SECS_PER_DAY;
const SECS_PER_DAY: u64 = 24 * 60 * 60;

pub fn parse_duration_str(input: &str) -> Result<Duration> {
	parse_duration(input)
		.map(|(_, dur)| dur)
		.map_err(|_| Error::msg("invalid duration"))
}

fn parse_duration(input: &str) -> IResult<&str, Duration> {
	let (input, years) = nom::combinator::opt(parse_years)(input)?;
	let (input, months) = nom::combinator::opt(parse_months)(input)?;
	let (input, days) = nom::combinator::opt(parse_days)(input)?;

	nom::combinator::eof(input)?;

	let mut secs = 0;

	if let Some(years) = years {
		secs += years * SECS_PER_YEAR;
	}

	if let Some(months) = months {
		secs += months * SECS_PER_MONTH;
	}

	if let Some(days) = days {
		secs += days * SECS_PER_DAY;
	}

	Ok((input, Duration::new(secs, 0)))
}

fn parse_years(input: &str) -> IResult<&str, u64> {
	let (input, years) = nom::character::complete::u64(input)?;
	let (input, _) = nom::character::complete::char('y')(input)?;

	Ok((input, years))
}

fn parse_months(input: &str) -> IResult<&str, u64> {
	let (input, months) = nom::character::complete::u64(input)?;
	let (input, _) = nom::character::complete::char('m')(input)?;

	Ok((input, months))
}

fn parse_days(input: &str) -> IResult<&str, u64> {
	let (input, days) = nom::character::complete::u64(input)?;
	let (input, _) = nom::character::complete::char('d')(input)?;

	Ok((input, days))
}
