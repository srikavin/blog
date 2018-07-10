import React from 'react';
import PostHeader from './PostHeader/PostHeader'
import {store} from '../../data/store';
import {NonIdealState} from '@blueprintjs/core';

import './Post.css'
import PostContent from './PostContent/PostContent';
import {Link} from 'react-router-dom';
import RequireAuth from '../Auth/RequireAuth/RequireAuth';
import DocumentTitle from 'react-document-title';

class Post extends React.Component {
    constructor(props) {
        super(props);
        this.onPostChange = this.onPostChange.bind(this);

        this.state = {
            error: false,
            post: {}
        }
    }

    onPostChange(post) {
        if (post.length === 0) {
            this.setState({
                error: true
            })
        }
        this.setState({
            post: post[0] || {}
        });
    }

    componentDidMount() {
        store.findAll('post', {slug: this.props.match.params.slug})
            .then(this.onPostChange)
            .catch(() => {
                this.setState({
                    error: true
                })
            });
    }

    render() {
        if (this.state.error) {
            return (
                <div>
                    <NonIdealState className={'header'} title={'This post could not be loaded'}
                                   visual={'warning-sign'}
                                   description={'There was an error attempting to load this post.'}
                                   action={<Link to={'/'}>Go home</Link>}/>
                </div>
            )
        }
        return (
            <div>
                {this.state.post.title ? <DocumentTitle title={this.state.post.title}/> : ''}
                <RequireAuth from={'/posts/' + this.props.match.params.slug}/>
                <PostHeader className="header" title={this.state.post.title} tags={this.state.post.tags}/>
                <PostContent content={this.state.post.contents}/>
            </div>
        )
    }
}

export default Post;