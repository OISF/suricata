#[macro_export]
macro_rules! take_until_and_consume (
 ( $i:expr, $needle:expr ) => (
    {
      let input: &[u8] = $i;

      let (rem, res) = ::nom::take_until!(input, $needle)?;
      let (rem, _) = ::nom::take!(rem, $needle.len())?;
      Ok((rem, res))
    }
  );
);
