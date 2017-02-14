(function() {var implementors = {};
implementors["bincode"] = ["impl&lt;'a, W:&nbsp;<a class='trait' href='https://doc.rust-lang.org/nightly/std/io/trait.Write.html' title='std::io::Write'>Write</a>&gt; <a class='trait' href='serde/ser/trait.Serializer.html' title='serde::ser::Serializer'>Serializer</a> for <a class='struct' href='bincode/serde/struct.Serializer.html' title='bincode::serde::Serializer'>Serializer</a>&lt;'a, W&gt;",];
implementors["maidsafe_utilities"] = ["impl&lt;'a, W&gt; <a class='trait' href='serde/ser/trait.Serializer.html' title='serde::ser::Serializer'>Serializer</a> for <a class='struct' href='bincode/serde/writer/struct.Serializer.html' title='bincode::serde::writer::Serializer'>Serializer</a>&lt;'a, W&gt; <span class='where'>where W: <a class='trait' href='https://doc.rust-lang.org/nightly/std/io/trait.Write.html' title='std::io::Write'>Write</a></span>",];
implementors["toml"] = ["impl <a class='trait' href='serde/ser/trait.Serializer.html' title='serde::ser::Serializer'>Serializer</a> for <a class='struct' href='toml/struct.Encoder.html' title='toml::Encoder'>Encoder</a>",];

            if (window.register_implementors) {
                window.register_implementors(implementors);
            } else {
                window.pending_implementors = implementors;
            }
        
})()
