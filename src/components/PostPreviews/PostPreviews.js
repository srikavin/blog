import React, {Component} from 'react';
import PostSnippet from './PostSnippet/PostSnippet';
import {PostStore} from '../../data/resource/post';

class PostPreviews extends Component {
    constructor(props) {
        super(props);
        this.state = {
            posts: []
        };
    }

    componentDidMount() {
        PostStore.getAll().then(e => {
            this.setState({
                posts: e
            });
        }).catch(console.error);
    }

    render() {
        return this.state.posts.map(e => <PostSnippet key={e.slug} post={e}/>);
    }
}

PostPreviews.propTypes = {};

export default PostPreviews;