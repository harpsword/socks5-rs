/// Exponent 指数避退
/// 
/// # Examples
/// 
/// ```
/// 
/// let exponent = Exponent::new(20, 1.1, 10);
/// 
/// let r = 10;
/// 
/// if r == 0 {
///     exponent.count();
///     sleep(exponent.now())
/// }
/// 
/// if exponent.terminate() {
///     return;
/// }
/// 
/// ```
pub struct Exponent {
    base: u64,
    factor: f64,
    now: u64,

    grow_counter: u32,
    grow_threshold: u32,
}

impl Exponent {
    pub fn new(base: u64, factor: f64, grow_threshold: u32) -> Self {
        Exponent{
            base,
            factor,
            now: base,
            grow_counter: 0,
            grow_threshold,
        }
    }

    pub fn reset(&mut self) {
        self.grow_counter = 0;
        self.now = self.base;
    }

    pub fn terminate(&self) -> bool {
        self.grow_counter >= self.grow_threshold
    }

    pub fn count(&mut self) {
        self.grow_counter += 1;
        let tmp = self.now as f64 * self.factor;
        self.now = tmp as u64;
    }

    pub fn now(&self) -> u64{
        self.now
    }
}

#[cfg(test)]
mod tests {
    use super::Exponent;

    
    #[test]
    fn exponent_grow() {
        let mut exponent = Exponent::new(1, 2.0, 10);
        let mut value: u64 = 1;
        for _ in 0..10 {
            exponent.count();
            value = value * 2;
            assert_eq!(exponent.now(), value);
        }
    }

    #[test]
    fn exponent_terminate() {
        let mut exponent = Exponent::new(1, 1.0, 10);
        for _ in 0..9 {
            exponent.count();
        }
        assert_eq!(exponent.terminate(), false);
        exponent.count();
        assert_eq!(exponent.terminate(), true);
    }

    #[test]
    fn exponent_reset() {
        let mut exponent = Exponent::new(1, 1.0, 10);
        for _ in 0..6 {
            exponent.count();
        }
        exponent.reset();
        for _ in 0..9 {
            exponent.count();
        }
        assert_eq!(exponent.terminate(), false);
        exponent.count();
        assert_eq!(exponent.terminate(), true); 
    }
}