import React, {Component} from 'react';
import {store} from '../../data/store';
import PostSnippet from './PostSnippet/PostSnippet';

class PostPreviews extends Component {
    constructor(props) {
        super(props);
        this.state = {
            posts: []
        };
    }

    componentDidMount() {
        store.findAll('post').then(e => {
            this.setState({
                posts: e
            })
        })
    }

    render() {
        return this.state.posts.map(e => <PostSnippet key={e.slug} post={e}/>);
    }
}

PostPreviews.propTypes = {};

export default PostPreviews;