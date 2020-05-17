use std::fmt;

#[derive(Debug)]
struct PasswordData {
    password: String,
    levels_bitmask: u16,
    acorns_bitmask: u16,
}

impl PasswordData {
    fn is_obtainable(&self) -> bool {
        let level_order_ok = (self.levels_bitmask + 1).is_power_of_two();
        let acorns_ok = self.acorns_bitmask & (self.levels_bitmask >> 1) == self.acorns_bitmask;

        level_order_ok && acorns_ok
    }
}

impl fmt::Display for PasswordData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.password)?;
        if self.is_obtainable() {
            write!(f, " (obtainable)")?;
        } else {
            write!(f, " (unobtainable)")?;
        }
        writeln!(f)?;

        write!(f, "Levels:")?;
        for i in 0..=10 {
            let c = if (self.levels_bitmask >> i) & 1 == 1 {
                'X'
            } else {
                '-'
            };
            write!(f, " {}", c)?;
        }
        writeln!(f, " ({})", self.levels_bitmask)?;

        write!(f, "Acorns:")?;
        for i in 0..=10 {
            let c = if (self.acorns_bitmask >> i) & 1 == 1 {
                'X'
            } else {
                '-'
            };
            write!(f, " {}", c)?;
        }
        writeln!(f, " ({})", self.acorns_bitmask)?;

        Ok(())
    }
}

const CHARACTER_SET: &[char; 17] = &[
    'B', 'C', 'D', 'F', 'G', 'H', 'J', 'K', 'L', 'M', 'N', 'P', 'Q', 'R', 'S', 'T', 'V',
];

/*
    Memory locations:
    08004D80 - Password validation code
    03005040 - Password data
    03005048 - Password length
    03005050 - Password cursor
    03004D84 - Levels bitmask
    03002A08 - Acorns bitmask
*/
fn process_password(password: &str) -> Result<PasswordData, &str> {
    let values: Vec<u32> = password
        .chars()
        .enumerate()
        .map(|(index, pass_char)| {
            CHARACTER_SET
                .iter()
                .position(|&c| c == pass_char)
                .expect("Invalid character") as u32
                + index as u32
        })
        .collect();

    // TODO: Cleanup

    let is_valid_password =
        (((((values[1] + values[2] & 0xFF) + values[3] & 0xFF) + values[4] & 0xFF) + values[5])
            * 0x1000000
            & 0xF000000)
            >> 0x18
            == values[0];

    if !is_valid_password {
        return Result::Err("Invalid password");
    }

    let var_5 = (values[3] - 3 & 0xC) as i32 >> 2;
    let var_2 = (values[1] - 1) * 0x40 | (values[2] - 2) * 4;
    let mut var_1 = false;
    let mut var_3 = 9;

    loop {
        let var_4 = (var_3 * 0x1000000) as i32 >> 0x18;
        if var_4 < 0 {
            break;
        }
        if (((var_2 & 0xFFFF) as i32 | var_5) as i32 >> var_4 & 1) == 0 {
            if var_1 {
                var_1 = false;
                break;
            }
        } else {
            var_1 = true;
        }
        var_3 = var_3 * 0x1000000 - 0x1000000 >> 0x18;
    }

    if var_1 {
        let levels_bitmask: u16 = var_2 as u16 | var_5 as u16;
        let acorns_bitmask: u16 = ((values[3] - 3 & 0x03) << 8) as u16
            | (values[4] as u16 - 4) * 0x10
            | values[5] as u16 - 5;
        Result::Ok(PasswordData {
            password: password.to_owned(),
            levels_bitmask,
            acorns_bitmask,
        })
    } else {
        Result::Err("Invalid password")
    }
}

/*
    Memory locations:
    08144D74 - Hardcoded password pointers
    08144D54 - Hardcoded password data
*/
fn reverse_hardcoded_password(values: &[u8]) -> String {
    values
        .iter()
        .enumerate()
        .map(|(index, &value)| CHARACTER_SET[value as usize - index as usize])
        .collect()
}

fn main_brute_force() {
    let mut password: [char; 6] = [' ', ' ', ' ', ' ', ' ', ' '];
    for &p0 in CHARACTER_SET.iter() {
        password[0] = p0;
        for &p1 in CHARACTER_SET.iter() {
            password[1] = p1;
            for &p2 in CHARACTER_SET.iter() {
                password[2] = p2;
                for &p3 in CHARACTER_SET.iter() {
                    password[3] = p3;
                    for &p4 in CHARACTER_SET.iter() {
                        password[4] = p4;
                        for &p5 in CHARACTER_SET.iter() {
                            password[5] = p5;

                            let p: String = password.iter().collect();
                            if let Ok(r) = process_password(&p) {
                                println!("{}", r);
                            }
                        }
                    }
                }
            }
        }
    }
}

fn main_test_passwords() {
    let tests = &[
        "QBBQBC", "NTTTTT", "NTTTTN", "PBBQBB", "QBCQBB", "SBFQBB", "DBKQBB", "NBTQBB", "PCTQBB",
        "RFTQBB", "CKTQBB", "MTTQBB", "MFKRPH",
    ];

    for test in tests {
        println!("{}: {:?}", test, process_password(test));
    }
}

fn main_hardcoded_passwords() {
    let hardcoded_password: [&[u8]; 5] = [
        &[0x09, 0x04, 0x09, 0x10, 0x0F, 0x0A], // 08144D54
        &[0x04, 0x03, 0x0E, 0x0B, 0x0D, 0x07], // 08144D5A
        &[0x06, 0x0E, 0x03, 0x06, 0x12, 0x0E], // 08144D60
        &[0x0F, 0x0E, 0x08, 0x03, 0x10, 0x09], // 08144D66
        &[0x0F, 0x0F, 0x0A, 0x0C, 0x07, 0x07], // 08144D6C
    ];

    for hp in hardcoded_password.iter() {
        println!("Hardcoded password: {}", reverse_hardcoded_password(hp));
    }
}

fn main() {
    main_test_passwords();
    main_hardcoded_passwords();
    main_brute_force();
}
