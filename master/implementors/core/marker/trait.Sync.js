(function() {var implementors = {};
implementors['bytes'] = ["impl <a class='trait' href='https://doc.rust-lang.org/nightly/core/marker/trait.Sync.html' title='core::marker::Sync'>Sync</a> for <a class='struct' href='bytes/alloc/struct.MemRef.html' title='bytes::alloc::MemRef'>MemRef</a>","impl <a class='trait' href='https://doc.rust-lang.org/nightly/core/marker/trait.Sync.html' title='core::marker::Sync'>Sync</a> for <a class='struct' href='bytes/struct.Bytes.html' title='bytes::Bytes'>Bytes</a>",];implementors['libc'] = [];implementors['thread_local'] = ["impl&lt;T: ?<a class='trait' href='https://doc.rust-lang.org/nightly/core/marker/trait.Sized.html' title='core::marker::Sized'>Sized</a> + <a class='trait' href='https://doc.rust-lang.org/nightly/core/marker/trait.Send.html' title='core::marker::Send'>Send</a>&gt; <a class='trait' href='https://doc.rust-lang.org/nightly/core/marker/trait.Sync.html' title='core::marker::Sync'>Sync</a> for <a class='struct' href='thread_local/struct.ThreadLocal.html' title='thread_local::ThreadLocal'>ThreadLocal</a>&lt;T&gt;","impl&lt;T: ?<a class='trait' href='https://doc.rust-lang.org/nightly/core/marker/trait.Sized.html' title='core::marker::Sized'>Sized</a> + <a class='trait' href='https://doc.rust-lang.org/nightly/core/marker/trait.Send.html' title='core::marker::Send'>Send</a>&gt; <a class='trait' href='https://doc.rust-lang.org/nightly/core/marker/trait.Sync.html' title='core::marker::Sync'>Sync</a> for <a class='struct' href='thread_local/struct.CachedThreadLocal.html' title='thread_local::CachedThreadLocal'>CachedThreadLocal</a>&lt;T&gt;",];implementors['itertools'] = ["impl&lt;'a, A&gt; <a class='trait' href='https://doc.rust-lang.org/nightly/core/marker/trait.Sync.html' title='core::marker::Sync'>Sync</a> for <a class='struct' href='itertools/struct.Stride.html' title='itertools::Stride'>Stride</a>&lt;'a, A&gt; <span class='where'>where A: <a class='trait' href='https://doc.rust-lang.org/nightly/core/marker/trait.Sync.html' title='core::marker::Sync'>Sync</a></span>","impl&lt;'a, A&gt; <a class='trait' href='https://doc.rust-lang.org/nightly/core/marker/trait.Sync.html' title='core::marker::Sync'>Sync</a> for <a class='struct' href='itertools/struct.StrideMut.html' title='itertools::StrideMut'>StrideMut</a>&lt;'a, A&gt; <span class='where'>where A: <a class='trait' href='https://doc.rust-lang.org/nightly/core/marker/trait.Sync.html' title='core::marker::Sync'>Sync</a></span>",];implementors['mio'] = ["impl&lt;H: <a class='trait' href='mio/trait.Handler.html' title='mio::Handler'>Handler</a>&gt; <a class='trait' href='https://doc.rust-lang.org/nightly/core/marker/trait.Sync.html' title='core::marker::Sync'>Sync</a> for <a class='struct' href='mio/struct.EventLoop.html' title='mio::EventLoop'>EventLoop</a>&lt;H&gt;","impl&lt;M: <a class='trait' href='https://doc.rust-lang.org/nightly/core/marker/trait.Send.html' title='core::marker::Send'>Send</a>&gt; <a class='trait' href='https://doc.rust-lang.org/nightly/core/marker/trait.Sync.html' title='core::marker::Sync'>Sync</a> for <a class='struct' href='mio/struct.Sender.html' title='mio::Sender'>Sender</a>&lt;M&gt;",];implementors['serde'] = [];

            if (window.register_implementors) {
                window.register_implementors(implementors);
            } else {
                window.pending_implementors = implementors;
            }
        
})()
