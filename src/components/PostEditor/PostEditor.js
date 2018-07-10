import React from 'react';

import './PostSnippet.css'
import Post from '../Post/Post';

class PostSnippet extends React.Component {
    constructor(props) {
        super(props);
        this.state = {
            auth: '',
            title: '',
            contents: '',
            tags: []
        }
    }

    render() {
        return (
            <Post post={{title: this.state.title, contents: this.state.contents, tags: this.state.tags}}/>
        )
    }
}

export default PostSnippet;