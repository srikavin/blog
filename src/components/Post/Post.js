import React from 'react';
import PostHeader from './PostHeader/PostHeader'
import PostContent from './PostContent/PostContent';
import {Link} from 'react-router-dom';
import DocumentTitle from 'react-document-title';

import {NonIdealState} from '@blueprintjs/core';
import {IconNames} from '@blueprintjs/icons';

import {PostStore} from '../../data/resource/post';
import './Post.css'

class Post extends React.Component {
    constructor(props) {
        super(props);
        this.onPostChange = this.onPostChange.bind(this);

        this.state = {
            error: false,
            loading: true,
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
            post: post[0] || {},
            loading: false
        });
    }

    componentDidMount() {
        PostStore.getBySlug(this.props.match.params.slug)
            .then(this.onPostChange)
            .catch((e) => {
                console.error(e);
                this.setState({
                    error: true
                })
            });
    }

    render() {
        if (this.state.error) {
            return (
                <div className="post-load-error">
                    <NonIdealState className={'header'} title={'This post could not be loaded'}
                                   description={'There was an error attempting to load this post.'}
                                   icon={IconNames.WARNING_SIGN}
                                   action={<Link to={'/'}>Go home</Link>}/>
                </div>
            )
        }
        return (
            <div>
                {!this.state.loading ? <DocumentTitle title={'sharath.pro | ' + this.state.post.title}/> : null}
                <PostHeader loading={this.state.loading}
                            className="header"
                            author={this.state.post.author}
                            title={this.state.post.title}
                            tags={this.state.post.tags}
                            createdTime={this.state.post.createdAt}
                            modifiedTime={this.state.post.updatedAt}
                />
                <PostContent content={this.state.post.contents}/>
            </div>
        )
    }
}

export default Post;